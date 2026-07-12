from core import *           #Allows for access to our core functions

if __name__ == "__main__":   #Default run check to start the program

	args = parse_args()      #Loads arguement parser

	try:
		if args.clear:                          #Checks for if the user used the clear arguement
			subprocess.run('cls', shell=True)   #If they did, run a screen clear function (Currently works on Windows PS)
		else:
			pass                                #If not then we move on
		OUI = loadOUI(update=args.update)              #We then load the OUI and update it if the user added the arguement for it
		devices = scan(subnet=args.subnet, timeout=args.timeout)   #Then we gather our devices
		resolveNames(devices, inSSDP=args.SSDP, DB=OUI)                    #And we resolve information on them
		display(devices, subnet=args.subnet, inSSDP=args.SSDP)     #Lastly, we display the results from everything

	except PermissionError:                                       #If at any point we get a permission error
		print("\n[!] Permission denied. Please run with sudo:")   #We print out a notifier that the program doesn't have the necessary permissions
		print(f"   sudo python3 {sys.argv[0]}\n")                 #As well as a notifier on how to corectly run the program
		sys.exit(1)                                               #Then we stop the program with the exit code of 1 to signify that the program failed

	except KeyboardInterrupt:                                     #If at any point we get a keyboard interrupt
		print("\n\n[!] Scan interrupted by user. Goodbye!\n")     #We print out a notifier about the interrupt
		sys.exit(0)                                               #And we exit with the exit code of 0 to show that the program didn't have any errors but was stopped because of the user
