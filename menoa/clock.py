# This is the loop that runs in the background
import time
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from utils.network_utils import connections_check

scanDelay=600 # Until I find a way to make the memory footprint smaller the delay just has to be really big. We could also just have a very specialized dataset which is much smaller and takes less time to scan, or have a dataset with rules which are more broad and if a file matches any of the rules its scanned with a better dataset
attestationDelay=600
networkDelay=2
processDelay=100

networkDatasetUpdate=3600*6 # Every 6 hours

class MyEventHandler(FileSystemEventHandler):
    # Detects any changes in the user's home, keeps track of all changed files in the last n seconds and scans them all

    def __init__(self):
        self.changed_files=[]

    def on_any_event(self, event: FileSystemEvent) -> None:
        #print(event.src_path)

        if event.src_path not in self.changed_files: self.changed_files.append(event.src_path)

    def scan_changed_files(self):
        # Scans the collected files

        print(self.changed_files)
        self.changed_files = []

print("Menoa clock starting....")

event_handler = MyEventHandler()
observer = Observer()
observer.schedule(event_handler, "/home/jack/", recursive=True)
observer.start()

scanClock=time.time()
attestationClock=time.time()
networkClock=time.time()
processClock=time.time()

scanChanged=False
attestationChanged=False
networkChanged=False
processChanged=False

try:
    while True:
        # Main loop for network, attestation, and process scanning
        
        if time.time()-scanClock >= scanDelay:
            print("Scanned")
            event_handler.scan_changed_files()
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
finally:
    observer.stop()
    observer.join()

