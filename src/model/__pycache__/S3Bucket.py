class S3Bucket(BucketEntity):
    def __init__(
        self,
        name: str,
        acl: Optional[str] = None,
        block_public_access: bool = True,
        policy: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        super().__init__(name, provider="aws", **kwargs)
        self.acl = acl
        self.block_public_access = block_public_access
        self.policy = policy

    def is_public(self):
        if self.block_public_access:
            return False

        if self.policy and '"Principal": "*"' in str(self.policy):
            return True

        if self.acl in ["public-read", "public-read-write"]:
            return True

        return False