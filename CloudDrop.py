'''
Created on Sep 13, 2014

@author: Samuel
'''
# Name : Samuel Benison Jeyaraj Victor
# Github Username: sambenison66
# Linkedin : https://www.linkedin.com/in/samuelbenison
import dropbox  # Dropbox library
import gnupg  # Gnupg library
import os # OS Library
import time # Time library
import httplib2 # httplib library for GDrive
# apiclient libraries for GDrive
from apiclient.discovery import build
from apiclient.http import MediaFileUpload
# oauth2client library for GDrive
from oauth2client.client import OAuth2WebServerFlow
# Watchdog Libraries
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Handler class which is called by watchdog.observers in the Main method
class MyHandler(FileSystemEventHandler):
    
    # This method is called whenever a new file is dropped in the monitoring folder
    def on_created(self, event):

        # print event
        file_path = event.src_path  # Path directory which is specified in the main method
        file_basename = os.path.basename(file_path) # Retrieving the dropped filename from the directory
        gnupg_file = file_basename+".gpg" # Gnupg version file name
        drop_url = "/Encripted/"+gnupg_file  # URL of the DropBox directory
        
        # Path to store the encrypted and decrypted files
        encripted_file ="C:\\DropBox\\Encripted\\"+file_basename
        decripted_file ="C:\\DropBox\\Decripted\\"+file_basename
        
        # Begining of DropBox Configuration
        # Get your app key and secret from the Dropbox developer website
        app_key = '---Your API Key----'
        app_secret = '---Your API Secret----'
              
        # DropBox OAuth connection
        flow_drop = dropbox.client.DropboxOAuth2FlowNoRedirect(app_key, app_secret)
         
        # Have the user sign in and authorize this token
        authorize_url_drop = flow_drop.start()
        print '1. Go to: ' + authorize_url_drop
        print '2. Click "Allow" (you might have to log in first)'
        print '3. Copy the authorization code.'
        code_drop = raw_input("Enter the authorization code here: ").strip()
        
        # This will fail if the user enters an invalid authorization code
        access_token, user_id = flow_drop.finish(code_drop)
        
        # Info of the linked account
        client = dropbox.client.DropboxClient(access_token)
        print 'linked account info: ', client.account_info()
        # End of DropBox Configuration
        
        # Begining of GDrive Configuration
        # Get your app key and secret from the GDrive developer website
        CLIENT_ID = '---Your API Key----'
        CLIENT_SECRET = '---Your API Secret----'
        
        #GDrive OAuth connection
        OAUTH_SCOPE = 'https://www.googleapis.com/auth/drive'
        
        ## Redirect URI for installed apps
        REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'
        
        # Run through the OAuth flow and retrieve credentials
        flow_drive = OAuth2WebServerFlow(CLIENT_ID, CLIENT_SECRET, OAUTH_SCOPE, REDIRECT_URI)
        authorize_url_drive = flow_drive.step1_get_authorize_url()
        print 'Go to the following link in your browser: ' + authorize_url_drive
        code_drive = raw_input('Enter verification code: ').strip()
        credentials_drive = flow_drive.step2_exchange(code_drive)
        
        # Create an httplib2.Http object and authorize it with our credentials
        http = httplib2.Http()
        http = credentials_drive.authorize(http)

        # Creta a Drive instance
        drive_service = build('drive', 'v2', http=http)
        
        # End of GDrive Configuration
            
        # GnuPG home directory to link with the program
        gpg = gnupg.GPG(gnupghome='C:\Program Files (x86)\GNU\GnuPG')
        gpg.encoding='UTF-8'
        
        # Key generated through GnuPG
        input_data = gpg.gen_key_input(key_type="RSA", key_length=1024, name_email='xyz@abc.com', name_real='Mr X')
        key = gpg.gen_key(input_data)

        # Read the dropped file from the given source path
        source_file = open(file_path, 'r')
        
        # Encrypt the file before dropping into DropBox
        encrypted_data = gpg.encrypt_file(source_file, recipients=['xyz@abc.com'],  passphrase='mydrop', output=encripted_file)
        
        # Read the encrypted file to sign the file
        f_enc = open( encripted_file, 'r')
        # Signing the File
        sign_file = gpg.sign_file(f_enc,keyid=key.fingerprint)
        signed_data = sign_file.data
        
        # Drop the signed file to DropBox
        response = client.put_file(drop_url,signed_data)
        print 'Dropbox uploaded: ', response
        
        print 'File encrypted and signed and uploaded to DropBox successfully.!'
        
        # Preparing the details of the file to insert in GDrive
        media_body = MediaFileUpload(encripted_file, mimetype='text/plain', resumable=True)
        body = {
          'title': gnupg_file, # file name to be used (VERY IMP)
          'description': 'A gpg document',
          'mimeType': 'text/plain'
        }

        # Insert the Encrypted file to GDrive
        file = drive_service.files().insert(body=body, media_body=media_body).execute()

        print 'GDrive uploaded: ', file

        print 'File encrypted and uploaded to GDrive successfully.!'
        
        # This line of code is to pause the program if you want to edit the dropped file before validation
        # When the file is edited then the validation will fail
        # Once the editing is done, give a choice from where file needs to be retrieved: GDrive or Dropbox
        while 1:
            print "To start retrieving process enter the source choice --> 'G' for GDrive / 'D' for Dropbox "
            source_text = raw_input("Enter Here: ").strip()
            source_text = source_text.upper()
            if source_text == 'D':
                # Contents to retrieve from DropBox
                # Get the DropBox metadata
                folder_metadata = client.metadata('/Encripted')
                print 'metadata: ', folder_metadata
                
                # Retrieve the dropped file from dropbox
                f, metadata = client.get_file_and_metadata(drop_url)
                out = open(file_basename, 'wb')
                out.write(f.read())
                out.close()
                print 'Downloaded: ', metadata
                
                # Open the retrieved file
                print 'Verifying the signed file...'
                retrieve_file = open(file_basename, "rb")
                retrieve_content = retrieve_file.read()
                
                # Verify the signature from the signed file content
                verify_content = gpg.verify(retrieve_content)
                # if the verification passed continue with decryption
                # else exit
                if verify_content:
                    print 'Successfully Verified.!'
                    print 'Decrypting the file...'
                    # Open the encrypted file to decrypt
                    f_enc = open( encripted_file, 'rb')
                    # Decrypt the file and store it in the output location
                    decrypt_data = gpg.decrypt_file(f_enc, None, passphrase='mydrop', output=decripted_file)
                    if decrypt_data:
                        print 'File Decrypted Successfully'
                        print 'Check the file here -> ', decripted_file
                    else:
                        print 'Decryption failed'
                        print 'File Retrieve aborted. Drop a new file and Start again'
                else:
                    print 'Signature Verification failed, Unable to decrypt the crashed file'
                    print 'File Retrieve aborted. Drop a new file and Start again'
                break
            elif source_text == 'G':
                # Contents to retrieve from DropBox
                # Get the metadata in an array
                drive_file = drive_service.files().list().execute()
                drive_item_list =  drive_file['items'] # Get the list of items from the array list
                # Check the title of the file to the expected file name and loop it till catching the file
                count = 0
                while 1:
                    take_file = drive_item_list[count] # counter value incremented for each time
                    # if the target file meatadat is reached, get it's corresponding download URL link
                    if take_file['title'] == gnupg_file:
                        download_url = take_file['downloadUrl']
                        break
                    else:
                        # Repeat the counter
                        count = count + 1
                        # In order to restrict the complexity of this infinite loop, counter is restricted to 100
                        if(count > 100):
                            download_url = ''
                            break
                # if the loop gets a downloadUrl, request the http to retrieve the file
                # print download_url
                if download_url:
                    # Request the http
                    resp, content = drive_service._http.request(download_url)
                    if resp.status == 200:
                        # If status is success, write the retrieved content to a file
                        # print 'Status: %s' % resp
                        out = open(file_basename, 'wb')
                        out.write(content)
                        out.close()
                        print 'Downloaded: ', resp
                        print content
                        print 'Decrypting the file....'
                        # Open the retrieved encrypted file to decrypt
                        f_enc = open( file_basename, 'rb')
                        # Decrypt the file and store it in the output location
                        decrypt_data = gpg.decrypt_file(f_enc, None, passphrase='mydrop', output=decripted_file)
                        if decrypt_data:
                            print 'File Decrypted Successfully'
                            print 'Check the file here -> ', decripted_file
                        else:
                            print 'Decryption failed'
                            print 'File Retrieve aborted. Drop a new file and Start again'
                    else:
                        print 'An error occurred: %s' % resp
                        print 'File Retrieve aborted. Drop a new file and Start again'
                else:
                    # The file doesn't have any content stored on Drive.
                    print 'No valid URL to download'
                    print 'File Retrieve aborted. Drop a new file and Start again'
                break
            else:
                # Repeat the loop if it is invalid keyword
                print 'Invalid Keyword.. Enter G or D '

        

# Main method which will do kick start the watchdog observers
if __name__ == "__main__":
    
    # Get the target directory from the user which needs to be monitored
    print 'Enter a folder path to start monitoring.'
    source_folder = raw_input("Enter here: ").strip()
    print 'Start dropping your files one by one..'
    # Call the MyHandler() method whenever a new file is dropped in the monitored directory
    event_handler = MyHandler()
    observer = Observer()
    observer.schedule(event_handler, source_folder, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    
# References:
# https://www.dropbox.com/developers/core/start/python
# https://pythonhosted.org/python-gnupg/
# https://pypi.python.org/pypi/watchdog
# http://pythonhosted.org//watchdog/api.html#module-watchdog.events
# https://developers.google.com/drive/web/quickstart/quickstart-python
# https://developers.google.com/drive/v1/reference/files/get
