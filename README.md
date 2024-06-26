[![GitHub stars](https://img.shields.io/github/stars/jkerai1/AzurePasswordProtectionCalculator?style=flat-square)](https://github.com/jkerai1/AzurePasswordProtectionCalculator/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/jkerai1/AzurePasswordProtectionCalculator?style=flat-square)](https://github.com/jkerai1/AzurePasswordProtectionCalculator/network)
[![GitHub issues](https://img.shields.io/github/issues/jkerai1/AzurePasswordProtectionCalculator?style=flat-square)](https://github.com/jkerai1/AzurePasswordProtectionCalculator/issues)
[![GitHub pulls](https://img.shields.io/github/issues-pr/jkerai1/AzurePasswordProtectionCalculator?style=flat-square)](https://github.com/jkerai1/AzurePasswordProtectionCalculator/pulls)

# AzurePasswordProtectionCalculator
Calculator for Azure Password Protection. The calculation for what passes as a valid password is difficult to comprehend so I attempted to make a calculator. 

https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad

There are notably a few issues:
- the azure in-built password list is hidden. UPDATE: List was dumped and now been included in the tool!
- not all string substitions are given on the documentation
- SSPR can bypass reuse of old password, something I cannot account for
- License Requirement of P1 / P2
- Tenant name matching isn't done when validating passwords on an AD DS domain 

# Score Calculation  
![image](https://github.com/jkerai1/AzurePasswordProtectionCalculator/assets/55988027/dc5a2f22-2fcf-4fee-9de1-8977b6f621fe)

# Fuzzy Matching Behaviour  

![image](https://github.com/jkerai1/AzurePasswordProtectionCalculator/assets/55988027/0905e4f3-4d35-4deb-b1a9-38cb32ffa28f)

# Normalization  

![image](https://github.com/jkerai1/AzurePasswordProtectionCalculator/assets/55988027/068e700b-f683-4e66-acd1-04dbaa0a7091)


# Password Requirements  

![image](https://github.com/jkerai1/AzurePasswordProtectionCalculator/assets/55988027/45086509-de88-4c91-87da-dffdc369dc99)
Ref https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy#microsoft-entra-password-policies

# Example  
![image](https://github.com/jkerai1/AzurePasswordProtectionCalculator/assets/55988027/5ec1f424-97dd-462f-af9c-042d441844c3)

# Audit  

![image](https://github.com/jkerai1/AzurePasswordProtectionCalculator/assets/55988027/c6ead3ad-06b3-4fa5-9ea4-6abc0cc73854)

# KQL 

AuditLogs  
| where OperationName == "Change password (self-service)"  
| where ResultDescription == "PasswordDoesnotComplyFuzzyPolicy"  
| extend User = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)  
| summarize count() by User  
| where count_ > 1  


Featured on Entra News Issue 26 https://entra.news/p/entranews-26-your-weekly-dose-of
