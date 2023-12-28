BannedPasswords = ['password','summer2016'] #Azures password list is hidden
AllowedLowerCase = "abcdefghijklmnopqrstuvwxyz"
AllowedUpperCase = "ABCDEFGHIJKLMNOPQRSTUVXYWZ"
AllowedSymbols = " @#$%^&*-_!+=[]{}|\:',.?/`~();<>\""
AllowedNumbers = "0123456789"
AllowedChars = AllowedLowerCase + AllowedUpperCase + AllowedSymbols + AllowedNumbers 
#https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy#microsoft-entra-password-policies

score = 0

def generate_edit_distance_one(s):
    splits = [(s[:i], s[i:]) for i in range(len(s) + 1)]
    deletes = [L + R[1:] for L, R in splits if R]
    substitutes = [L + c + R[1:] for L, R in splits if R for c in (AllowedLowerCase + AllowedSymbols + AllowedNumbers)]
    inserts = [L + c + R for L, R in splits for c in (AllowedLowerCase + AllowedSymbols + AllowedNumbers)]
    return set(deletes + substitutes + inserts)


print("Substring matching is used on the normalized password to check for the user's first and last name as well as the tenant name. Tenant name matching isn't done when validating passwords on an AD DS domain controller for on-premises hybrid scenarios.")
FirstName = input("First Name?: ")
LastName = input("Last Name?: ")
TenantName = input("Tenant name? (Note: Other Domains associated to the tenant are allowed just not the one used for UPN): ")
    
    
while True: 

    inp = input("password to test: ")
    
    #Password Requirement Check
    
    if len(inp) <= 256 and len(inp) >= 8:
        for i in inp:
            if i in AllowedLowerCase:
                ContainsLowerCase = 1
            if i in AllowedUpperCase:
                ContainsUpperCase = 1
            if i in AllowedNumbers:
                ContainsNumber = 1
            if i in AllowedSymbols:
                ContainsSymbol = 1
            if i not in AllowedChars: #filter out if invalid characters AFTER length check
                invalidflag = 1
        if (ContainsNumber + ContainsLowerCase + ContainsUpperCase +ContainsSymbol) < 3 or invalidflag ==1:
                print("invalid Password. Does not meet requirements.")
                print("Contains Number: " + str(ContainsNumber))
                print("Contains LowerCase: " + str(ContainsLowerCase))
                print("Contains UpperCase: " + str(ContainsUpperCase))
                print("Contains Symbol: " + str(ContainsSymbol))
                print("invalid character: " + str(invalidflag))
                break;
        else:
        
        #Password Protection Begins
        
        #Step 1: Normalization 
        
            normalized_inp = inp.lower()
        
        # Substitution/leetspeak, we have to do this AFTER checking the contain number check
        
        #These are the substitutions listed in the Azure documentation
            normalized_inp = normalized_inp.replace("0", "o")
            normalized_inp = normalized_inp.replace("1","l")
            normalized_inp = normalized_inp.replace("$","s")
            normalized_inp = normalized_inp.replace("@","a")
        
        #Guess Work Leet Speak from valid chars. Ref: https://www.gamehouse.com/blog/leet-speak-cheat-sheet/
            normalized_inp = normalized_inp.replace("5", "s")
        
           #Step 2: Check if password is considered Banned (min length of 4)
            
            #Fuzzy Match: edit distance of 1 comparison. We can do this is use Levenshtein Distance or create a fuzz set
            
            temp = inp
            
            for word in BannedPasswords:
                if len(word) >4: 
                    SetToCheck = generate_edit_distance_one(word) #Only generate fuzzer if length is at least 4
                   #print(SetToCheck)
                    if (word in normalized_inp) or (word in inp):
                        #print("initial score: " + str(score))
                        score = score + temp.count(word) #add based of count of banned password
                        temp = temp.replace(word,'') #remove banned word to prevent further fuzzy match
                        #print("Temp: " + temp)
                        print("password directly contains banned phrase: " + word)
                    
                    #temp = temp.replace("0", "o").replace("1","l").replace("$","s").replace("@","a").replace("5", "s")
                    
                    for i in SetToCheck:
                        if i in temp:
                            print("password contains banned word " + word + " Fuzz Matcher: " + i)
                           # print("Temp: " + temp)
                            score = score + temp.count(i)
                            temp = temp.replace(i,'') #remove the banned word so we don't count it
                            
            #Count Each Remaining Character AFTER we exited loop. do not overlap character count from banned passwords
            score = int(score) + int(len(temp))
            
        
        # Substring Matching (On Specific Terms) https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad#substring-matching-on-specific-terms
        
        #TenantName/userName. The documentation/testing seems to suggest that distance is not affected here.
        #This Check is applied AFTER Normalisation
            if (FirstName in normalized_inp and len(FirstName)>=4) or (LastName in normalized_inp and len(LastName)>=4) or (TenantName in normalized_inp and len(TenantName)>=4):
                #print(inp)
                print("invalid Password, contains first/last/tenantName")
                break; #Documentation Example suggests its rejected regardless of the score
        
        
        if int(score) >= 5:
            print("Valid Password")
        else:
            print("Invalid Password")
        print("normalised Password: " + str(normalized_inp))
        print("Score: " + str(score))
        
    else:
        print("Password Does not meet length requirement - Try again")
