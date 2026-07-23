def extract_resource_name_from_path(path: str) -> str:
    """
    Estrae logicamente il nome della risorsa da un endpoint REST.
    Se il path termina in o contiene '{id}', restituisce il segmento precedente.

    Esempi:
        /api/users/{id} -> users
        /api/posts/{id}/comments -> posts (o comments a seconda del design, ma ci fermiamo a prima di id)
    """
    segments = [s for s in path.split("/") if s]
    resource_name = "resource"
    for i, seg in enumerate(segments):
        if seg == "{id}" and i > 0:
            resource_name = segments[i - 1]
            break
    return resource_name
