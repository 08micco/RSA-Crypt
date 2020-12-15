# Lavet i Python 3.9
# Lavet af Mikkel Wissing
from random import randint as tilfældigt_tal  # Bruges til at finde et tilfældigt tal mellem 2 værdier
from sympy import primerange  # Bruges til at generere en liste af primtal

# ASCII: http://www.asciitable.com/
alphabet = {97: 'a', 98: 'b', 99: 'c', 100: 'd', 101: 'e', 102: 'f', 103: 'g', 104: 'h', 105: 'i', 106: 'j', 107: 'k',
            108: 'l', 109: 'm', 110: 'n', 111: 'o', 112: 'p', 113: 'q', 114: 'r', 115: 's', 116: 't', 117: 'u',
            118: 'v', 119: 'w', 120: 'x', 121: 'y', 122: 'z', 145: 'æ', 155: 'ø', 134: 'å', 95: '_', 42: '*', 44: ',',
            46: '.', 45: '-', 61: '=', 92: '\'', 49: '1', 50: '2', 51: '3', 52: '4', 53: '5', 54: '6', 55: '7', 56: '8',
            57: '9', 48: '0', 32: ' '}

# Funktion, som generere de to primtal p og q
def generate_primes():
    primes = list(primerange(50, 500))  # Laver en list med mulige primtal fra 50 til 1000 via modulet sympy
    # https://www.sympy.org/en/index.html 
    index1 = tilfældigt_tal(0, len(primes)-1) # Finder et tilfældigt tal mellem 0 og længden af listen
    index2 = tilfældigt_tal(0, len(primes)-1) # Her gøres det samme bare med et andet tal, da vi skal have to forskellige primtal
    # Tjekker om primtallene er det samme, og kører funktionne igen hvis dette er tilfældet
    if(index1 == index2):
        generate_primes()
    
    # Finder a og b via et tilfældigt tal som bestemmer hvilket tal i tabellen(list) der vælges
    a = primes[index1]
    b = primes[index2]
    return a, b  # Returnere de to primtal så vi kan definere dem som p og q ved næste linje

# To primtal vælges som p og q via funktionen generate_primes
p, q = generate_primes()
print('p: ', p)
print('q: ', q)

n = p * q  # n er produktet af p og q
print('n: ', n)

phi = (p - 1) * (q - 1)  # Eulers phi funktion: φ(n) = (p - 1)(q - 1)
print('phi: ', phi)

# Funktionen her finder den største fælles faktor for de to primtal
def sfd(p,q):
    while q != 0:
        p, q = q, p%q
    return p

# Funktionen tjekker om de er inbyrdesprimisk
def is_coprime(x, y):
    return sfd(x, y) == 1

# Denne funktion finder e, som er 1 < e < φ(n)(phi) samt indbyrdes primisk med n og φ(n)
def find_e():
    available_e = []  # Laver en tom liste, som vi senere fylder med alle de mulige værdier for e
    for i in range(1, phi):  # For alle tal som er større end 1 og mindre end φ(n): 1 < e < φ(n)
        if(is_coprime(i, phi) and is_coprime(i, n)):  # Hvis tallet er indbyrdes primisk med φ(n) samt n, 
            # tilføjes det til listen available_e
            available_e.append(i)
    index = tilfældigt_tal(0, len(available_e)-1)  # Finder et tilfældigt tal mellem og længden af listen
    # lidt ligesom da vi fandt printallene, og returnere derefter tallet som ligger på indexnummerets plads i listen
    return available_e[index]

e = find_e()  # Sætter vores e værdi til nummeret fundet over
print('e: ', e)

# https://stackoverflow.com/questions/44044143/why-is-my-rsa-implementation-in-python-not-working?noredirect=1&lq=1
# Funktionen her udregner d efter Euklids udvidede algoritme
def find_d(e, phi): 
    a, b, u = 0, phi, 1
    while(e > 0):  # Mens e er større end 0
        q = b // e  # // her er en operator i pyhton (såvel som mange andre sprog), som hedder floor division. Man dividere og runder ned
        e, a, b, u = b % e, u, e, a-q*u
    if (b == 1):  # Vi skal her også tjekke om det giver 1 ligesom eksemplet tidligere.
        return a % phi
    else:  # Hvis det ikke er indbyrdes primisk
        print('Skal være indbyrdes primisk')

d = find_d(e, phi)  # d sættes til den fundne værdi i funktionen over
print('d: ', d)


# Funktion der krypterer en string(text) via den offentlig nøgle
def rsa_encrypt(text):
    encrypted_msg = []  # Laver en tom list til at gemme de krypterede tal
    txt = let_to_num(text)  # Omdanner teksten til tallene i alphabet og gemmer dem i txt variablen
    for num in txt:  # For hvert tal i txt
        encrypted_msg.append(pow(num, e) % n)  # Bruger krypteringsformlen til at kryptere tallene, og tilføjer dem
        # så til den tomme liste lavet før
    return encrypted_msg


# Funktion der dekrypterer en list med krypterede tal(text) via den private nøgle
def rsa_decrypt(text):
    decrypted_msg = []  # Laver en tom list til at gemme den dekrypterede besked i
    for num in text:  # For hvert tal i listen lavet i rsa_encrypt
        decrypted_msg.append(pow(num, d) % n)  # Dekryptere tallene via formlen og tilføjer dem til den tomme list
    return num_to_let(decrypted_msg)  # Returnere de dekrypterede tal omdannet til tekst


# Funktion, som omdanner bogstaver og tegn i teksten til tal
def let_to_num(text):
    num_list = []  # En tom liste laves, for at kunne opbevare tallene.
    for letter in text:
        for num in alphabet:  # For hvert tal i dictionarien alphabet.
            if letter == alphabet[num]:  # Hvis bogstavet er det samme som bogstavspartneren til num, fx alphabet[
                # 3] giver ‘c’
                num_list.append(num)  # Så tilføjes tallet til num_list
    return num_list


# Funktion, som omdanner en list med tal til string
def num_to_let(encrypted_list):
    txt = ''  # Laver en tom tekst til at gemme den omdannede tekst senere
    for item in encrypted_list:  # For hver ting i list
        txt += alphabet[item]  # alphabet[item] returnerer højre side i et dictionary par. Dette lægges til
        # strengen text.
    return txt


user_text = input('Denne tekst bliver krypteret: \n')  # Får input fra brugeren i form af tekst
encrypted = rsa_encrypt(user_text)  # Kryptere teksten og gemmer det i variablen encrypted
print('Teksten krypteret: %s' % encrypted)  # Printer det ud til console
print('\n.....\n')
decrypted = rsa_decrypt(encrypted)  # Dekryptere teksten og gemmer et i variablen decrypted
print('Teksten dekrypteret: %s\n' % decrypted)  # Printer den dekrypterede tekst ud til console

input('Tryk på en knap for at afslutte')  # Hvis dette ikke er her, vil filen lukke af sig.


'''
# Skrive til fil
def listToString(list):  # Laver list om til string
    listToStr = ' '.join([str(elem) for elem in list])  # Tager texten og opdeler den efter mellemrum
    return listToStr

def StringToList(string):  # Laver string om til liste
    str_list = string.split()  # Laver det først om til liste, som indeholder strings
    int_list = list(map(int, str_list))  # Laver så listen om til en integer liste bestående af tal og ikke tekst
    return int_list

user_text = input('Denne tekst bliver krypteret: \n')  # Får input fra brugeren i form af tekst
with open('Krypteret besked.txt', 'w') as f:  # Åbner filen Krypteret besked.txt og skriver til den('w', write)
    encrypted = rsa_encrypt(user_text)  # Kryptere beskeden i variablen encrypted
    f.write(listToString(encrypted))  # Omdanner listen til string, og skriver det til filen

# Filen kan nu sendes rundt omkring, og folk kan ikke læse den da den er krytperet.
# Den kan derfor sendes sikkert til modtageren, og modtageren kan med sin nøgle dekryptere tekstfilen.s

print('Teksten krypteret: %s' % encrypted)
print('\n.....\n')
with open('Krypteret besked.txt', 'r') as f:  # Åbner filen i read mode('r')
    decrypted = rsa_decrypt(StringToList(f.read()))  # Gemmer filteksten i variablen decrypted 

print('Teksten dekrypteret: %s\n' % decrypted)  # Printer den dekrypterede tekst ud til console

input('Tryk på en knap for at afslutte')  # Hvis dette ikke er her, vil filen lukke af sig.
'''