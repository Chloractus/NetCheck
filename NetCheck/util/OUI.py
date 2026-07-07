import os             #Allows the program to access files and other system functions
import sys            #Allows the program to do basically the same things as import os but slightly more modernized
import requests       #Allows the program to perform HTTP GET and other HTTP methods

OUI_FILE = "oui.txt"                                     #This variable holds the name for the file that we are going to put the OUI into
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"   #This variable contains the link for the OUI

def getOUI(mac: str) -> str:
    """
    This function exists purely to handle getting the first 8 characters in a given MAC Address

    Args:
        mac: A String representing any given valid MAC Address

    Returns:
        String. This program returns a String representing the first 8 digits in the given MAC Address
    """
    return mac[:8]       #Returns a slice of the MAC Address (This slice is where companies place their OUIs)

def download_OUI() -> None:
    """
    Handles downloading the OUI via copying the entire OUI into an easily accessable text file

    Returns:
        None. This function can not / should not return anything. It's main purpose is to safely download the IEEE OUI Database so it can be used to find OUIs.
    """
    print("[*] Downloading IEEE OUI Database...")      #Prints out a notifier that we are downloading the OUI

    response = requests.get(OUI_URL, timeout=5)        #Attempts an HTTP GET on the OUI URL
    response.raise_for_status()                        #Raises error if it occured

    with open(OUI_FILE, "w", encoding="utf-8") as f:   #We open the OUI File
        f.write(response.text)                         #And we write the contents of the OUI URL into the file

    print(f"[+] Saved database to {OUI_FILE}")         #Prints out a notifier that we successfully saved the database
    sys.exit(0)                                        #Exits with the exit code 0 because the download was successful

def loadOUI() -> dict:
    """
    This function parses the OUI into a usable dictionary that we can search through.

    Returns:
        Dictionary. This function returns a Dictionary of MAC Addresses and their OUIs.
    """
    
    if not os.path.exists(OUI_FILE):                                             #First, we check to see if the OUI is downloaded
        print("[!] Database not found. (Run NetCheck -u or NetCheck --update)")  #If it isn't, we print out a notifier that the database was not found
        return sys.exit(1)                                                       #Then we exit with an exit code of 1 because the program ran into an error

    ouiDB = {}                                                         #This is the dictionary that is going to hold all the OUIs

    with open(OUI_FILE, "r", encoding="utf-8", errors="ignore") as f:  #Opens the OUI File in Read mode
        for line in f:                        #Loops through every line
            if "(hex)" not in line:           #Checks if the line doesn't has "(hex)" in it
                continue                      #If it doesn't, we move on to the next line

            parts = line.split("(hex)")       #If it does, we split the line at "(hex)"
            if len(parts) != 2:               #We check to see if we didn't get 2 parts from the split
                continue                      #If we didn't, then we continue to the next line
            oui = parts[0].strip().replace("-", ":")    #If we did, then we take the first part, cut out the unnecessary stuff, replace "-" with ":" and make it a variable representing the OUI
            vendor = parts[1].strip()                   #We also grab the second part, cut out the unnecessary stuff and make it a variable representing the vendor / company related to the OUI

            ouiDB[oui.lower()] = vendor                 #This creates the full dictionary item using the OUI as the key and the vendor as the value

    return ouiDB                     #After we go through every line, we return the list of OUIs

def getVendor(mac: str, ouiDB: dict) -> str:
    """
    Grabs the OUI vendor based on a given MAC Address and the OUI Database.

    Args:
        mac: This is a String representing a MAC Address to check for an OUI
        ouiDB: This is a Dictionary of the OUIs and the vendors they represent
    
    Returns:
        String. This function returns a String representing the OUI Vendor of the given MAC Address
    """
    try:
        oui = getOUI(mac)              #First, we use getOUI() to get the first 8 characters of the given MAC Address

    except ValueError:                 #Checks to make sure that we didn't get a value error
        return "Inavlid Mac Address"   #If we did, that means that we got an invalid MAC Address
    
    return ouiDB.get(oui, "Unknown Vendor")  #If we didn't, we search through the OUI Database to see if the MAC has an OUI Vendor. If it doesn't, we just return "Unknown Vendor"