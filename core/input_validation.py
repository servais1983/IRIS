"""
Module de validation des entrées pour IRIS.
Fournit des fonctionnalités pour la validation et la sanitization des données.
"""

import os
import re
import yaml
import json
import logging
import bleach
import html
import sqlparse
from jsonschema import validate, ValidationError
from jsonschema.exceptions import ValidationError as JSONSchemaValidationError
from typing import Dict, Any, List, Optional, Union, cast, Callable, TypeVar
from dataclasses import dataclass
from enum import Enum
from functools import wraps
import ipaddress
from datetime import datetime

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ValidationType(Enum):
    """Types de validation."""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    EMAIL = "email"
    URL = "url"
    IP = "ip"
    DATE = "date"
    JSON = "json"
    SQL = "sql"

@dataclass
class ValidationRule:
    """Règle de validation."""
    type: ValidationType
    required: bool = True
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    allowed_values: Optional[List[Any]] = None
    custom_validator: Optional[callable] = None

class InputValidator:
    """Validateur d'entrées."""
    
    def __init__(self, config_path: str):
        """
        Initialise le validateur.
        
        Args:
            config_path: Chemin vers le fichier de configuration
        """
        self.config = self._load_config(config_path)
        self.rules = self._init_rules()
        self.sanitizers = self._init_sanitizers()
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Charge la configuration depuis le fichier YAML."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                if not isinstance(config, dict):
                    raise ValueError("La configuration doit être un dictionnaire")
                return cast(Dict[str, Any], config)
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la configuration: {e}")
            raise
            
    def _init_rules(self) -> Dict[str, ValidationRule]:
        """Initialise les règles de validation."""
        rules = {}
        for field, rule in self.config['validation_rules'].items():
            rules[field] = ValidationRule(
                type=ValidationType(rule['type']),
                required=rule.get('required', True),
                min_length=rule.get('min_length'),
                max_length=rule.get('max_length'),
                pattern=rule.get('pattern'),
                allowed_values=rule.get('allowed_values'),
                custom_validator=rule.get('custom_validator')
            )
        return rules
        
    def _init_sanitizers(self) -> Dict[str, callable]:
        """Initialise les sanitizers."""
        return {
            'html': self._sanitize_html,
            'sql': self._sanitize_sql,
            'json': self._sanitize_json,
            'shell': self._sanitize_shell,
            'path': self._sanitize_path
        }
        
    def validate(self, data: Dict[str, Any], schema: Optional[Dict[str, Any]] = None) -> bool:
        """
        Valide des données.
        
        Args:
            data: Données à valider
            schema: Schéma de validation JSON
            
        Returns:
            True si les données sont valides, False sinon
        """
        try:
            if schema:
                validate(instance=data, schema=schema)
            else:
                for field, value in data.items():
                    if field in self.rules:
                        if not self._validate_field(field, value):
                            return False
            return True
        except JSONSchemaValidationError as e:
            logger.error(f"Erreur de validation: {e}")
            return False
        except Exception as e:
            logger.error(f"Erreur lors de la validation: {e}")
            return False
            
    def _validate_field(self, field: str, value: Any) -> bool:
        """
        Valide un champ selon sa règle.
        
        Args:
            field: Nom du champ
            value: Valeur à valider
            
        Returns:
            True si le champ est valide, False sinon
        """
        try:
            rule = self.rules[field]
            
            # Vérification du type
            if not self._validate_type(value, rule.type):
                return False
                
            # Vérification de la longueur
            if isinstance(value, str):
                if rule.min_length and len(value) < rule.min_length:
                    return False
                if rule.max_length and len(value) > rule.max_length:
                    return False
                    
            # Vérification du pattern
            if rule.pattern and isinstance(value, str):
                if not re.match(rule.pattern, value):
                    return False
                    
            # Vérification des valeurs autorisées
            if rule.allowed_values and value not in rule.allowed_values:
                return False
                
            # Validation personnalisée
            if rule.custom_validator and not rule.custom_validator(value):
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de la validation du champ {field}: {e}")
            return False
            
    def _validate_type(self, value: Any, type_: ValidationType) -> bool:
        """
        Valide le type d'une valeur.
        
        Args:
            value: Valeur à valider
            type_: Type attendu
            
        Returns:
            True si le type est valide, False sinon
        """
        try:
            if type_ == ValidationType.STRING:
                return isinstance(value, str)
            elif type_ == ValidationType.INTEGER:
                return isinstance(value, int)
            elif type_ == ValidationType.FLOAT:
                return isinstance(value, float)
            elif type_ == ValidationType.BOOLEAN:
                return isinstance(value, bool)
            elif type_ == ValidationType.EMAIL:
                return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', str(value)))
            elif type_ == ValidationType.URL:
                return bool(re.match(r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', str(value)))
            elif type_ == ValidationType.IP:
                return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', str(value)))
            elif type_ == ValidationType.DATE:
                return bool(re.match(r'^\d{4}-\d{2}-\d{2}$', str(value)))
            elif type_ == ValidationType.JSON:
                try:
                    json.loads(str(value))
                    return True
                except json.JSONDecodeError:
                    return False
            elif type_ == ValidationType.SQL:
                try:
                    sqlparse.parse(str(value))
                    return True
                except Exception:
                    return False
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de la validation du type: {e}")
            return False
            
    def sanitize(self, data: Union[str, Dict[str, Any]], type_: str) -> Union[str, Dict[str, Any]]:
        """
        Sanitize des données.
        
        Args:
            data: Données à sanitizer
            type_: Type de sanitization
            
        Returns:
            Données sanitizées
        """
        try:
            if type_ not in self.sanitizers:
                raise ValueError(f"Type de sanitization inconnu: {type_}")
                
            if isinstance(data, str):
                return self.sanitizers[type_](data)
            elif isinstance(data, dict):
                return {k: self.sanitize(v, type_) for k, v in data.items()}
            else:
                return data
                
        except Exception as e:
            logger.error(f"Erreur lors de la sanitization: {e}")
            raise
            
    def _sanitize_html(self, data: str) -> str:
        """
        Sanitize du HTML.
        
        Args:
            data: Données à sanitizer
            
        Returns:
            Données sanitizées
        """
        try:
            # Liste des balises et attributs autorisés
            allowed_tags = self.config['sanitization']['html']['allowed_tags']
            allowed_attrs = self.config['sanitization']['html']['allowed_attrs']
            
            cleaned = bleach.clean(
                data,
                tags=allowed_tags,
                attributes=allowed_attrs,
                strip=True
            )
            return str(cleaned) if cleaned is not None else ""
        except Exception as e:
            logger.error(f"Erreur lors de la sanitization HTML: {e}")
            return html.escape(data)
            
    def _sanitize_sql(self, data: str) -> str:
        """
        Sanitize du SQL.
        
        Args:
            data: Données à sanitizer
            
        Returns:
            Données sanitizées
        """
        try:
            # Échappement des caractères spéciaux
            return data.replace("'", "''").replace('"', '""')
        except Exception as e:
            logger.error(f"Erreur lors de la sanitization SQL: {e}")
            return data
            
    def _sanitize_json(self, data: str) -> str:
        """
        Sanitize du JSON.
        
        Args:
            data: Données à sanitizer
            
        Returns:
            Données sanitizées
        """
        try:
            # Validation et formatage du JSON
            parsed = json.loads(data)
            return json.dumps(parsed)
        except Exception as e:
            logger.error(f"Erreur lors de la sanitization JSON: {e}")
            return data
            
    def _sanitize_shell(self, data: str) -> str:
        """
        Sanitize des commandes shell.
        
        Args:
            data: Données à sanitizer
            
        Returns:
            Données sanitizées
        """
        try:
            # Échappement des caractères spéciaux
            return re.sub(r'[;&|`$]', '', data)
        except Exception as e:
            logger.error(f"Erreur lors de la sanitization shell: {e}")
            return data
            
    def _sanitize_path(self, data: str) -> str:
        """
        Sanitize des chemins de fichiers.
        
        Args:
            data: Données à sanitizer
            
        Returns:
            Données sanitizées
        """
        try:
            # Normalisation et validation du chemin
            return os.path.normpath(data).replace('..', '')
        except Exception as e:
            logger.error(f"Erreur lors de la sanitization de chemin: {e}")
            return data
            
    def validate_and_sanitize(self, data: Dict[str, Any], schema: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Valide et sanitize des données.
        
        Args:
            data: Données à traiter
            schema: Schéma de validation (optionnel)
            
        Returns:
            Données validées et sanitizées
        """
        try:
            if not self.validate(data, schema):
                raise ValueError("Données invalides")
                
            result = {}
            for field, value in data.items():
                if field in self.rules:
                    type_ = self.rules[field].type.value
                    result[field] = self.sanitize(value, type_)
                else:
                    result[field] = value
                    
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors de la validation et sanitization: {e}")
            raise

def main():
    """Fonction principale pour tester le module."""
    try:
        # Initialisation
        validator = InputValidator("config/secrets.yaml")
        
        # Test de validation
        data = {
            "username": "test_user",
            "email": "test@example.com",
            "age": 25,
            "website": "https://example.com"
        }
        
        schema = {
            "type": "object",
            "properties": {
                "username": {"type": "string", "minLength": 3},
                "email": {"type": "string", "format": "email"},
                "age": {"type": "integer", "minimum": 18},
                "website": {"type": "string", "format": "uri"}
            },
            "required": ["username", "email"]
        }
        
        is_valid = validator.validate(data, schema)
        print(f"Données valides: {is_valid}")
        
        # Test de sanitization
        html_data = "<script>alert('XSS')</script><p>Hello</p>"
        sanitized_html = validator.sanitize(html_data, "html")
        print(f"HTML sanitizé: {sanitized_html}")
        
        sql_data = "'; DROP TABLE users; --"
        sanitized_sql = validator.sanitize(sql_data, "sql")
        print(f"SQL sanitizé: {sanitized_sql}")
        
        # Test de validation et sanitization
        result = validator.validate_and_sanitize(data)
        print(f"Résultat final: {result}")
        
    except Exception as e:
        logger.error(f"Erreur dans la fonction principale: {e}")
        raise

if __name__ == "__main__":
    main()

T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])

def validate_ip(func: F) -> F:
    """Décorateur pour valider les adresses IP"""
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            # Vérifier si l'argument est une adresse IP valide
            ip = kwargs.get('ip') or args[0]
            ipaddress.ip_address(ip)
            return func(*args, **kwargs)
        except ValueError as e:
            logger.error(f"Adresse IP invalide: {str(e)}")
            raise ValueError(f"Adresse IP invalide: {ip}")
    return cast(F, wrapper)

def validate_port(func: F) -> F:
    """Décorateur pour valider les ports"""
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            # Vérifier si l'argument est un port valide
            port = kwargs.get('port') or args[0]
            port_num = int(port)
            if not (0 <= port_num <= 65535):
                raise ValueError(f"Port invalide: {port}")
            return func(*args, **kwargs)
        except ValueError as e:
            logger.error(f"Port invalide: {str(e)}")
            raise ValueError(f"Port invalide: {port}")
    return cast(F, wrapper)

def validate_date(func: F) -> F:
    """Décorateur pour valider les dates"""
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            # Vérifier si l'argument est une date valide
            date_str = kwargs.get('date') or args[0]
            datetime.strptime(date_str, '%Y-%m-%d')
            return func(*args, **kwargs)
        except ValueError as e:
            logger.error(f"Date invalide: {str(e)}")
            raise ValueError(f"Date invalide: {date_str}")
    return cast(F, wrapper)

def validate_email(func: F) -> F:
    """Décorateur pour valider les adresses email"""
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            # Vérifier si l'argument est une adresse email valide
            email = kwargs.get('email') or args[0]
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(pattern, email):
                raise ValueError(f"Email invalide: {email}")
            return func(*args, **kwargs)
        except ValueError as e:
            logger.error(f"Email invalide: {str(e)}")
            raise ValueError(f"Email invalide: {email}")
    return cast(F, wrapper)

def validate_path(func: F) -> F:
    """Décorateur pour valider les chemins de fichiers"""
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            # Vérifier si l'argument est un chemin valide
            path = kwargs.get('path') or args[0]
            if not path or not isinstance(path, str):
                raise ValueError(f"Chemin invalide: {path}")
            return func(*args, **kwargs)
        except ValueError as e:
            logger.error(f"Chemin invalide: {str(e)}")
            raise ValueError(f"Chemin invalide: {path}")
    return cast(F, wrapper)

def validate_hash(func: F) -> F:
    """Décorateur pour valider les hashes"""
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            # Vérifier si l'argument est un hash valide
            hash_str = kwargs.get('hash') or args[0]
            if not re.match(r'^[a-fA-F0-9]{32,}$', hash_str):
                raise ValueError(f"Hash invalide: {hash_str}")
            return func(*args, **kwargs)
        except ValueError as e:
            logger.error(f"Hash invalide: {str(e)}")
            raise ValueError(f"Hash invalide: {hash_str}")
    return cast(F, wrapper)

def validate_domain(func: F) -> F:
    """Décorateur pour valider les noms de domaine"""
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            # Vérifier si l'argument est un nom de domaine valide
            domain = kwargs.get('domain') or args[0]
            pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
            if not re.match(pattern, domain):
                raise ValueError(f"Domaine invalide: {domain}")
            return func(*args, **kwargs)
        except ValueError as e:
            logger.error(f"Domaine invalide: {str(e)}")
            raise ValueError(f"Domaine invalide: {domain}")
    return cast(F, wrapper)

def validate_url(func: F) -> F:
    """Décorateur pour valider les URLs"""
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            # Vérifier si l'argument est une URL valide
            url = kwargs.get('url') or args[0]
            pattern = r'^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$'
            if not re.match(pattern, url):
                raise ValueError(f"URL invalide: {url}")
            return func(*args, **kwargs)
        except ValueError as e:
            logger.error(f"URL invalide: {str(e)}")
            raise ValueError(f"URL invalide: {url}")
    return cast(F, wrapper) 