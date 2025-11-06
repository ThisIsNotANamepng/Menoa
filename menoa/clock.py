# This is the loop that runs in the background
import time
from utils.network_utils import connections_check

clamDelay=600 # Until I find a way to make the memory footprint smaller the delay just has to be really big. We could also just have a very specialized dataset which is much smaller and takes less time to scan, or have a dataset with rules which are more broad and if a file matches any of the rules its scanned with a better dataset
attestationDelay=600
networkDelay=2
processDelay=100

networkDatasetUpdate=3600*6 # Every 6 hours

print("Menoa clock starting....")

scanClock=time.time()
attestationClock=time.time()
networkClock=time.time()
processClock=time.time()

scanChanged=False
attestationChanged=False
networkChanged=False
processChanged=False

filesToScan = ["~/Downloads"]

print("Started")

def scan_files(filesToScan):
    #TODO: Add logic for actually scanning files
    print(filesToScan)

try:
    while True:
        # Main loop for network, attestation, and process scanning
        
        if time.time()-scanClock >= clamDelay:
            print("Scanned")
            scan_files(filesToScan)
            scanClock=time.time()

        if time.time()-attestationClock >= attestationDelay:
            print("Attested")
            # Attestation logic
            attestationClock=time.time()

        if time.time()-networkClock >= networkDelay:
            print("Networked")
            connections_check(False, True)
            networkClock=time.time()

        if time.time()-processClock >= processDelay:
            print("Processed")
            # Process logic
            processClock=time.time()

        time.sleep(1)

except:
    print("Failure")

