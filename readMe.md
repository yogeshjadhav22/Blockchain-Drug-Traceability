#This the blockchain for Drug traceability

#This blockchain has the following features:
	Possibility of adding multiple nodes to the blockchain
    Proof of Work (PoW)
    Simple conflict resolution between nodes
    Transactions with RSA encryption

#The blockchain client has the following features:
    Wallets generation using Public/Private key encryption (based on RSA algorithm)
    Generation of transactions with RSA encryption

#This github repository also contains 2 dashboards:
    "Blockchain Frontend" for miners
    "Blockchain Client" for users to generate wallets and send coins


##How to run the code
    ## Firstly Create Virtual Environment on your project folder
	
	1. To start a blockchain node, go to blockchain folder and execute the command below: python blockchain.py -p 5000
	
	2. To start the blockchain client, go to blockchain_client folder and execute the command below: python blockchain_client.py -p 8080
    
	3. You can add a new node to blockchain by executing the same command and specifying a port that is not already used. 
	   For example, python blockchain.py -p 8081
    
    4. You can access the blockchain frontend and blockchain client dashboards from your browser by going to 
	   localhost:5000 and localhost:8080

