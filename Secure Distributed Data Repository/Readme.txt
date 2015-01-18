README.txt
###############################

How to Compile code:

1. cd to the project folder
2. make

_________________________________________
How to run client and Server:

1. To run client, run ./client
2. To run server, run ./server


Note: clientDir, client2Dir and ServerDir folders with appropriate certificates and keys have been provided in the project folder for testing purpose only. The client/server executables can be moved to these folders to test multiple client scenarios.

_________________________________________
Client Side UI:

Welcome to Secure Directory Service!!


Please make a choice:
1) Establish Session
2) GET Document
3) PUT Document
4) DELEGATE
5) Terminate Session
6) Exit


Establishing session (Option 1):


To establish the session between client and server, Press 1 and enter the IP address of Server. You can run all other options only after establishing the session.


GET Document (Option 2):


To retrieve a document from the server, press 2. It prompts for the Document ID. Provide the UID of document that you want to fetch. 


PUT Document (Option 3):


To put a document on the server, press 3. UI would need the name of the file that you want to put on the server. It then asks for the Security-flag that the client would like to associate with that file. The request is then sent to the server and appropriate response is received based on the action taken by the server.


SNIPPET:
Okay!! So you would like to put a file on the server.
Please enter the filename (Absolute Path Max size: 50):
12345.txt
Is this a new file (Is the UID not known?). Enter 1/0 for Yes/No
1
Which security property would you like to have?
1) None
2) Confidentiality
3) Integrity
1
The request is: @PUT:NONE:NIL:sakshi
Received: 1025214017126725206755363
The new UID generated for your file is: 1025214017126725206755363
Please store this UID to access this file in future.
File has been stored on the server successfully.


DELEGATE (Option 4):

To run the delegate command, press 4. The UI asks for ID of the document that client wants to delegate. Further, the client has to provide the other Client’s ID whom the delegation is done for. Along with this, the delegate rights, validity period of the delegation request and progation flag are required to be set.

SNIPPET:
Please enter the UID of the file:
1025214017126725206755363 
Enter the client ID(Enter ALL to allow everyone):
ALL
What rights do you want to delegate:
1. GET
2. PUT
3. BOTH
1
Please enter the validityPeriod.
12
Do you want to allow propagation? (0/1):
0
The request is: @DEL:1025214017126725206755363:ALL:GET:12:0
Received: true
Delegation Successful.

TERMINATE SESSION:

To terminate the session, press 5.
