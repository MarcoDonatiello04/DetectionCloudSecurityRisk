"""
RC-004 SECURE: schema con QueryDepthLimiter e MaxAliasesLimiter.
"""
import strawberry
from strawberry.asgi import GraphQL
from strawberry.extensions import QueryDepthLimiter, MaxAliasesLimiter


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


# SECURE: depth e aliases limitati
app = GraphQL(
    strawberry.Schema(
        query=Query,
        extensions=[
            QueryDepthLimiter(max_depth=5),
            MaxAliasesLimiter(max_aliases=10),
        ]
    )
)
