# AzurePasswordProtectionCalculator
Calculator for Azure Password Protection. The calculation for what passes as a valid password is difficult to comprehend so I attempted to make a calculator. 

https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad

There are notably a few issues:
- the azure in-built password list is hidden
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
