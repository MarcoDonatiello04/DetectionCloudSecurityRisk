import os
import pytest
from src.core.terraform_scanner import TerraformScanner
from src.model.BucketEntity import BucketEntity

@pytest.fixture
def dummy_tf_file(tmp_path):
    tf_content = """
    resource "aws_s3_bucket" "test_bucket" {
      bucket = "my-secure-bucket"
      acl    = "private"
      
      versioning {
        enabled = true
      }
      
      server_side_encryption_configuration {
        rule {
          apply_server_side_encryption_by_default {
            sse_algorithm = "AES256"
          }
        }
      }

      tags = {
        Environment = "Prod"
      }
    }
    """
    file_path = tmp_path / "dummy.tf"
    file_path.write_text(tf_content)
    return str(file_path)

def test_parse_bucket_entity(dummy_tf_file):
    scanner = TerraformScanner()
    
    # Esegui scansione limitata al dummy file
    parsed_data = scanner.parse_file(dummy_tf_file)
    assert parsed_data is not None
    
    resources = scanner.extract_resources(parsed_data)
    
    assert len(resources) == 1
    
    # Recupera il bucket parsato
    bucket: BucketEntity = resources[0]
    
    # Verifica il tipo e la classe corretta
    assert isinstance(bucket, BucketEntity)
    assert bucket.provider_type == "aws_s3_bucket"
    assert bucket.name == "my-secure-bucket"
    assert bucket.acl == "private"
    assert bucket.versioning_enabled is True
    assert bucket.encryption_enabled is True
    assert bucket.tags.get("Environment") == "Prod"
