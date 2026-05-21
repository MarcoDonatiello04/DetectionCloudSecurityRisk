import re

def normalize_path(path):
    """
    Normalizza i percorsi estraendo i parametri variabili per permettere 
    il confronto tra il codice (es. Flask) e le specifiche OpenAPI.
    Esempi:
    - /users/<int:id> -> /users/VAR
    - /users/{id} -> /users/VAR
    """
    # Flask style: /users/<int:id> -> /users/VAR
    path = re.sub(r'<[^>]+>', 'VAR', path)
    # OpenAPI style: /users/{id} -> /users/VAR
    path = re.sub(r'\{[^}]+\}', 'VAR', path)
    return path
