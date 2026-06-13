from NetCheck.core import *

if __name__ == "__main__":

	args = parse_args()

	try:
		if args.clear:
			subprocess.run('cls', shell=True)
		else:
			pass
		devices = scan(subnet=args.subnet, timeout=args.timeout)
		resolveNames(devices)
		display(devices, subnet=args.subnet)

	except PermissionError:
		print("\n[!] Permission denied. Please run with sudo:")
		print(f"   sudo python3 {sys.argv[0]}\n")
		sys.exit(1)

	except KeyboardInterrupt:
		print("\n\n[!] Scan interrupted by user. Goodbye!\n")
		sys.exit(0)
