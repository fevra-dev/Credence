Sometimes the most dangerous production system is a public GitHub repo with "private" in the name.  
  
KrebsOnSecurity and GitGuardian reported that a CISA contractor had a public repository called Private-CISA containing 844 MB of material, including CI/CD logs, Kubernetes manifests, Terraform code, GitHub workflows, internal documentation, cloud references, and secret-related files. Krebs reported that the exposed material included AWS GovCloud admin credentials and plaintext passwords for internal systems. GitGuardian says the repo was created in November 2025 and taken offline on May 15.  
  
I do not care how mature the organization is. If secrets can be committed, synced, backed up, and published by one person, the control is not real yet.  
  
Practical lesson: treat GitHub like part of your production perimeter. Enforce secret scanning at the organization level. Block public repo creation where it is not needed. Use short-lived credentials. Rotate anything exposed immediately. Monitor commits, not only runtime alerts. And please, never use Git as a backup drive for operational secrets.  
  
Attackers do not need zero-days when your deployment map, keys, and passwords are gift-wrapped in version history.

https://github.com/GitGuardian

https://docs.gitguardian.com/
