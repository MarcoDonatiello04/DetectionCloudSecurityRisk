from typing import Dict, Any, Optional, Literal, List
from src.core.policy_engine import PolicyEngine
from src.rules.bucket_policies.no_public_access_rule import NoPublicAccessRule

class BucketEntity:
    def __init__(
        self,
        name: str,
        provider: str = "aws_s3_bucket",
        acl: Optional[str] = None,
        policies: Optional[Any] = None,
        versioning_enabled: bool = False,
        encryption_enabled: bool = False,
        public_access_block: bool = False,
        logging_enabled: bool = False,
        tags: Optional[Dict[str, str]] = None,
        region: Optional[str] = None,
        raw_config: Optional[Dict[str, Any]] = None,
        object_ownership: Optional[Literal["BucketOwnerPreferred", "ObjectWriter", "BucketOwnerEnforced"]] = None
    ):
        self.name = name
        self.provider_type = provider
        self.acl = acl
        self.policies = policies
        self.versioning_enabled = versioning_enabled
        self.encryption_enabled = encryption_enabled
        self.public_access_block = public_access_block
        self.logging_enabled = logging_enabled
        self.tags = tags or {}
        self.region = region
        self.raw_config = raw_config or {}
        self.object_ownership = object_ownership


    def evaluate_risks(self) -> List[str]:
        """
        Valuta i rischi di sicurezza seguendo le direttive:
        - ignorare le ACL come meccanismo principale e se enforced non considerarle vincolanti ma...
        - segnalare l'uso delle ACL come rischio (sempre)
        - verificare che tutto passi da policy
        """
        risks = []
        
        # 1. Ignorare le ACL come meccanismo principale ma segnalarne l'uso come rischio
        if self.acl:
            if self.object_ownership == "BucketOwnerEnforced":
                # Se è Enforced, le ACL sono esplicitamente disabilitate (ignoriamo le ACL dal punto di vista dell'accesso)
                risks.append(f"Avviso: E' stata specificata un'ACL ({self.acl}) ma l'ownership è BucketOwnerEnforced. L'ACL verrà ignorata da AWS.")
                """Gestione della configuazione delle policy in presenza di ACL:"""""
                def handle_acl_with_policies():
                    if self.policies:
                        # Se ci sono policy, verificare se regolano correttamente gli accessi
                        # (questa parte è complessa e dipende dalla struttura delle policy, quindi qui facciamo solo un controllo di base)
                        risks.append("Nota: Anche se l'ACL è ignorata, assicurarsi che le policy associate regolino correttamente gli accessi.")
                    else:
                        risks.append("Avviso: Nonostante l'ACL sia ignorata, non sono state trovate policy associate. Verificare che gli accessi siano regolati tramite policy.")
            else:
                # Altrimenti segnalare l'uso delle ACL come rischio
                risks.append("RISCHIO: L'uso delle ACL è configurato. Si raccomanda di disabilitare le ACL (es. usando BucketOwnerEnforced) e usare policy.")
        
        # 2. Verificare che tutto passi da policy (Bucket Policy / IAM Policy associazioni)
        if not self.policies:
            risks.append("RISCHIO: Nessuna resource policy trovata (es. Bucket Policy). Verificare che gli accessi siano regolati tramite policy e non ACL.")
        else:
            # 3. Valutazione approfondita della policy tramite PolicyEngine
            engine = PolicyEngine()
            engine.register_rule(NoPublicAccessRule())
            policy_risks = engine.evaluate_entity(self)
            risks.extend(policy_risks)
            
        return risks

    def __repr__(self):
        return f"BucketEntity(name={self.name}, provider={self.provider_type})"