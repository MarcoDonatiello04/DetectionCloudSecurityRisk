"""
RC-004: GraphQL schema senza QueryDepthLimiter e senza max_aliases.
Un attacker può inviare query arbitrariamente profonde o batch di mutation
causando esaurimento memoria/CPU del server.
"""
import strawberry
from strawberry.asgi import GraphQL


@strawberry.type
class Post:
    id: int
    title: str
    author: "User"


@strawberry.type
class User:
    id: int
    name: str
    posts: list[Post]


@strawberry.type
class Query:
    @strawberry.field
    def user(self, id: int) -> User:
        return get_user(id)


# VULNERABLE: nessun QueryDepthLimiter, nessun max_aliases, nessun complexity limit
schema = strawberry.Schema(query=Query)
app = GraphQL(schema)
