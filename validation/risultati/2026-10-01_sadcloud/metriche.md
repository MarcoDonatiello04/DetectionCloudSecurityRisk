# Metriche di accuratezza — sadcloud

| Categoria | Voci | VP | FN | Candidati | Fuori perimetro | Recall | Recall nel perimetro | Precisione minima |
|---|---|---|---|---|---|---|---|---|
| IAC | 84 | 51 | 33 | 0 | 0 | 61% | 61% | 25% |
| Totale | 84 | 51 | 33 | 0 | 0 | 61% | 61% | 25% |

## Voci

| Voce | Categoria | Punto | Esito | Come | Segnalazioni / motivo |
|---|---|---|---|---|---|
| S01 certificate_transparency_disabled | IAC | modules/aws/acm | VP | decisione | checkov:CKV_AWS_234:module.acm.aws_acm_certificate.main[0] |
| S02 stack_with_role | IAC | modules/aws/cloudformation | FN | decisione | Nessun controllo segnala l'assegnazione di un ruolo IAM allo stack; quelli sul ruolo ne valutano solo la policy. |
| S03 stack_with_secret_output | IAC | modules/aws/cloudformation | FN | decisione | Nessun controllo cerca segreti negli output dello stack (CKV_AWS_124 riguarda le notifiche). |
| S04 no_data_logging | IAC | modules/aws/cloudtrail | FN | decisione | Nessun controllo sui data event del trail. |
| S05 no_global_services_logging | IAC | modules/aws/cloudtrail | FN | decisione | Nessun controllo sui servizi globali; CKV_AWS_67 riguarda le regioni. |
| S06 no_log_file_validation | IAC | modules/aws/cloudtrail | VP | decisione | checkov:CKV_AWS_36:module.cloudtrail.aws_cloudtrail.duplicate[0] |
| S07 no_logging | IAC | modules/aws/cloudtrail | FN | decisione | Nessun controllo su enable_logging disattivato. |
| S08 duplicated_global_services_logging | IAC | modules/aws/cloudtrail | FN | decisione | Configurazione d'account (trail duplicato), non valutata dai controlli presenti. |
| S09 not_configured | IAC | modules/aws/cloudtrail | FN | decisione | Assenza di CloudTrail: configurazione d'account non visibile nei manifest. |
| S10 alarm_without_actions | IAC | modules/aws/cloudwatch | FN |  |  |
| S11 config_recorder_not_configured | IAC | modules/aws/config | FN | decisione | CKV2_AWS_48 valuta l'ambito del recorder, non la sua assenza. |
| S12 ebs_default_encryption_disabled | IAC | modules/aws/ebs | VP | decisione | checkov:CKV_AWS_106:module.ebs.aws_ebs_encryption_by_default.main[0] |
| S13 ebs_volume_unencrypted | IAC | modules/aws/ebs | VP | decisione | checkov:CKV_AWS_3:module.ebs.aws_ebs_volume.main[0] |
| S14 ebs_snapshot_unencrypted | IAC | modules/aws/ebs | FN | decisione | Nessun controllo sulle snapshot EBS. |
| S15 disallowed_instance_type | IAC | modules/aws/ec2 | FN | decisione | Nessun controllo sui tipi di istanza ammessi. |
| S16 instance_with_public_ip | IAC | modules/aws/ec2 | VP | decisione | checkov:CKV_AWS_88:module.ec2.aws_instance.main[0] |
| S17 instance_with_user_data_secrets | IAC | modules/aws/ec2 | VP | decisione | checkov:CKV_AWS_46:module.ec2.aws_instance.main[0] |
| S18 security_group_opens_all_ports_to_all | IAC | modules/aws/ec2 | VP | decisione | checkov:CKV_AWS_24:module.ec2.aws_security_group.all_ports_to_all[0], checkov:CKV_AWS_25:module.ec2.aws_security_group.all_ports_to_all[0] |
| S19 security_group_opens_all_ports_to_self | IAC | modules/aws/ec2 | FN | decisione | Sul gruppo aperto a sé stesso falliscono solo controlli sulla descrizione e sull'associazione. |
| S20 security_group_opens_icmp_to_all | IAC | modules/aws/ec2 | FN | decisione | I controlli sulle porte 22, 3389 e 80 non descrivono l'ICMP aperto. |
| S21 security_group_opens_known_port_to_all | IAC | modules/aws/ec2 | VP | decisione | checkov:CKV_AWS_24:module.ec2.aws_security_group.known_port_to_all[0], checkov:CKV_AWS_25:module.ec2.aws_security_group.known_port_to_all[0] |
| S22 security_group_opens_plaintext_port | IAC | modules/aws/ec2 | FN | decisione | Sul gruppo con porta in chiaro falliscono solo controlli sulla descrizione e sull'associazione. |
| S23 security_group_opens_port_range | IAC | modules/aws/ec2 | FN | decisione | CKV_AWS_24 segnala la porta 22 aperta, non l'uso di intervalli di porte. |
| S24 security_group_opens_port_to_all | IAC | modules/aws/ec2 | FN | decisione | Sul gruppo con porta aperta a tutti falliscono solo controlli sulla descrizione e sull'associazione. |
| S25 security_group_whitelists_aws_ip_from_banned_region | IAC | modules/aws/ec2 | FN | decisione | Nessun controllo sugli intervalli IP di AWS fuori regione. |
| S26 security_group_whitelists_aws | IAC | modules/aws/ec2 | FN | decisione | Nessun controllo sugli intervalli IP di AWS. |
| S27 ec2_security_group_whitelists_unknown_cidrs | IAC | modules/aws/ec2 | FN | decisione | Nessun controllo sui CIDR sconosciuti. |
| S28 ec2_unused_security_group | IAC | modules/aws/ec2 | VP | decisione | checkov:CKV2_AWS_5:module.ec2.aws_security_group.unused_security_group[0] |
| S29 ec2_unneeded_security_group | IAC | modules/aws/ec2 | FN | decisione | Nessun controllo sui CIDR non bloccabili. |
| S30 ec2_unexpected_security_group | IAC | modules/aws/ec2 | FN | decisione | Nessun controllo sul formato dei CIDR. |
| S31 ec2_overlapping_security_group | IAC | modules/aws/ec2 | FN | decisione | Nessun controllo sulla sovrapposizione dei CIDR. |
| S32 ecr_scanning_disabled | IAC | modules/aws/ecr | VP | decisione | checkov:CKV_AWS_163:module.ecr.aws_ecr_repository.main[0] |
| S33 ecr_repo_public | IAC | modules/aws/ecr | VP | decisione | checkov:CKV_AWS_32:module.ecr.aws_ecr_repository_policy.mainecrpolicy[0] |
| S34 out_of_date | IAC | modules/aws/eks | VP | decisione | checkov:CKV_AWS_339:module.eks.aws_eks_cluster.example[0] |
| S35 no_logs | IAC | modules/aws/eks | VP | decisione | checkov:CKV_AWS_37:module.eks.aws_eks_cluster.example[0] |
| S36 publicly_accessible | IAC | modules/aws/eks | VP | decisione | checkov:CKV_AWS_39:module.eks.aws_eks_cluster.example[0] |
| S37 globally_accessible | IAC | modules/aws/eks | VP | decisione | checkov:CKV_AWS_38:module.eks.aws_eks_cluster.example[0] |
| S38 elasticsearch_logging_disabled | IAC | modules/aws/elasticsearch | VP | decisione | checkov:CKV_AWS_317:module.elasticsearch.aws_elasticsearch_domain.main[0] |
| S39 elasticsearch_open_access | IAC | modules/aws/elasticsearch | FN | decisione | I controlli presenti (accesso granulare, VPC) non descrivono una policy di accesso aperta. |
| S40 no_access_logs | IAC | modules/aws/elb | FN | decisione | Sul load balancer classico nessun controllo sui log di accesso. |
| S41 no_access_logs | IAC | modules/aws/elbv2 | VP | decisione | checkov:CKV_AWS_91:module.elbv2.aws_lb.main[0] |
| S42 no_deletion_protection | IAC | modules/aws/elbv2 | VP | decisione | checkov:CKV_AWS_150:module.elbv2.aws_lb.main[0] |
| S43 older_ssl_policy | IAC | modules/aws/elbv2 | VP | decisione | checkov:CKV_AWS_103:module.elbv2.aws_lb_listener.main[0] |
| S44 glacier_public | IAC | modules/aws/glacier | VP | decisione | checkov:CKV_AWS_167:module.glacier.aws_glacier_vault.main[0] |
| S45 password_policy_minimum_length | IAC | modules/aws/iam | FN | decisione | Manca il controllo sulla lunghezza minima della password. |
| S46 password_policy_no_lowercase_required | IAC | modules/aws/iam | VP | decisione | checkov:CKV_AWS_11:module.iam.aws_iam_account_password_policy.main[0] |
| S47 password_policy_no_numbers_required | IAC | modules/aws/iam | VP | decisione | checkov:CKV_AWS_12:module.iam.aws_iam_account_password_policy.main[0] |
| S48 password_policy_no_uppercase_required | IAC | modules/aws/iam | VP | decisione | checkov:CKV_AWS_15:module.iam.aws_iam_account_password_policy.main[0] |
| S49 password_policy_no_symbol_required | IAC | modules/aws/iam | VP | decisione | checkov:CKV_AWS_14:module.iam.aws_iam_account_password_policy.main[0] |
| S50 password_policy_reuse_enabled | IAC | modules/aws/iam | FN | decisione | Manca il controllo sul riuso delle password. |
| S51 password_policy_expiration_threshold | IAC | modules/aws/iam | VP | decisione | checkov:CKV_AWS_9:module.iam.aws_iam_account_password_policy.main[0] |
| S52 managed_allows_passrole | IAC | modules/aws/iam | FN | decisione | Nessun controllo identifica la policy gestita con iam:PassRole su *. |
| S53 inline_role_policy | IAC | modules/aws/iam | VP | decisione | checkov:CKV_AWS_286:module.iam.aws_iam_role_policy.inline_role_policy[0] |
| S54 inline_group_policy | IAC | modules/aws/iam | VP | decisione | checkov:CKV_AWS_286:module.iam.aws_iam_group_policy.inline_group_policy[0] |
| S55 inline_user_policy | IAC | modules/aws/iam | VP | decisione | checkov:CKV_AWS_286:module.iam.aws_iam_user_policy.inline_user_policy[0], checkov:CKV_AWS_40:module.iam.aws_iam_user_policy.inline_user_policy[0] |
| S56 assume_role_policy_allows_all | IAC | modules/aws/iam | VP | decisione | checkov:CKV_AWS_60:module.iam.aws_iam_role.allow_all[0] |
| S57 assume_role_no_mfa | IAC | modules/aws/iam | FN | decisione | CKV_AWS_60 valuta i principal ammessi, non l'assenza di MFA ed external ID. |
| S58 admin_iam_policy | IAC | modules/aws/iam | VP | decisione | checkov:CKV_AWS_62:module.iam.aws_iam_policy.policy[0] |
| S59 admin_not_indicated_policy | IAC | modules/aws/iam | VP | decisione | checkov:CKV_AWS_62:module.iam.aws_iam_policy.admin_not_indicated_policy[0] |
| S60 key_rotation_disabled | IAC | modules/aws/kms | VP | decisione | checkov:CKV_AWS_7:module.kms.aws_kms_key.main[0] |
| S61 kms_key_exposed | IAC | modules/aws/kms | VP | decisione | checkov:CKV_AWS_33:module.kms.aws_kms_key.exposed[0] |
| S62 lightsail_in_use | IAC | modules/aws/lightsail | FN |  |  |
| S63 no_minor_upgrade | IAC | modules/aws/rds | VP | decisione | checkov:CKV_AWS_226:module.rds.aws_db_instance.main[0] |
| S64 backup_disabled | IAC | modules/aws/rds | VP | decisione | checkov:CKV_AWS_133:module.rds.aws_db_instance.main[0] |
| S65 storage_not_encrypted | IAC | modules/aws/rds | VP | decisione | checkov:CKV_AWS_16:module.rds.aws_db_instance.main[0] |
| S66 single_az | IAC | modules/aws/rds | VP | decisione | checkov:CKV_AWS_157:module.rds.aws_db_instance.main[0] |
| S67 rds_publicly_accessible | IAC | modules/aws/rds | VP | decisione | checkov:CKV_AWS_17:module.rds.aws_db_instance.main[0] |
| S68 parameter_group_ssl_not_required | IAC | modules/aws/redshift | VP | decisione | checkov:CKV_AWS_105:module.redshift.aws_redshift_parameter_group.main[0] |
| S69 parameter_group_logging_disabled | IAC | modules/aws/redshift | VP | decisione | checkov:CKV_AWS_71:module.redshift.aws_redshift_cluster.main[0] |
| S70 cluster_publicly_accessible | IAC | modules/aws/redshift | VP | decisione | checkov:CKV_AWS_87:module.redshift.aws_redshift_cluster.main[0] |
| S71 cluster_no_version_upgrade | IAC | modules/aws/redshift | VP | decisione | checkov:CKV_AWS_141:module.redshift.aws_redshift_cluster.main[0] |
| S72 cluster_database_not_encrypted | IAC | modules/aws/redshift | VP | decisione | checkov:CKV_AWS_64:module.redshift.aws_redshift_cluster.main[0] |
| S73 allow_cleartext | IAC | modules/aws/s3 | FN | decisione | Nessun controllo sulla policy che vieta HTTP. |
| S74 no_default_encryption | IAC | modules/aws/s3 | VP | decisione | checkov:CKV_AWS_145:module.s3.aws_s3_bucket.main |
| S75 no_logging | IAC | modules/aws/s3 | VP | decisione | checkov:CKV_AWS_18:module.s3.aws_s3_bucket.public[0] |
| S76 no_versioning | IAC | modules/aws/s3 | VP | decisione | checkov:CKV_AWS_21:module.s3.aws_s3_bucket.main |
| S77 website_enabled | IAC | modules/aws/s3 | FN | decisione | Nessun controllo sull'hosting statico del bucket. |
| S78 s3_getobject_only | IAC | modules/aws/s3 | VP | decisione | checkov:CKV_AWS_283:module.s3.aws_iam_policy_document.getonly |
| S79 s3_public | IAC | modules/aws/s3 | VP | decisione | checkov:CKV_AWS_283:module.s3.aws_iam_policy_document.public |
| S80 no_dkim_enabled | IAC | modules/aws/ses | FN | decisione | Nessun controllo su DKIM. |
| S81 identity_world_policy | IAC | modules/aws/ses | VP | decisione | checkov:CKV_AWS_283:module.ses.aws_iam_policy_document.main |
| S82 topic_world_policy | IAC | modules/aws/sns | VP | decisione | checkov:CKV_AWS_283:module.sns.aws_iam_policy_document.sns-topic-policy |
| S83 queue_world_policy | IAC | modules/aws/sqs | VP | decisione | checkov:CKV_AWS_168:module.sqs.aws_sqs_queue_policy.main[0] |
| S84 sqs_server_side_encryption_disabled | IAC | modules/aws/sqs | FN | decisione | Nessun controllo sulla cifratura della coda SQS. |

Segnalazioni in ambito: 219 — corrispondenti 54, vere non documentate 0, falsi positivi 0, da classificare 165.
