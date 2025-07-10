# This is the loop that runs in the background
import time
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

scanDelay=5
attestationDelay=3600
networkDelay=5
processDelay=10
delayDelay=1

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
        print("=====   SCANNING    =====")
        self.changed_files = []





event_handler = MyEventHandler()
observer = Observer()
observer.schedule(event_handler, "/home/jack/", recursive=True)
observer.start()

clock=time.time()
print(clock)

changed=False

try:
    while True:
        # Main loop for network, attestation, and process scanning


        difference = time.time() - clock

        print("Clock", clock, "difference", difference)

        
        if difference >= scanDelay:
            print("THING")
            event_handler.scan_changed_files()
            changed=True

        if changed:
            print(clock)
            clock=time.time()
            changed=False


        time.sleep(1)
finally:
    observer.stop()
    observer.join()
