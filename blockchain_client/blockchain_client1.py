from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
dt={}
import requests
from flask import Flask, jsonify, request, render_template


class Transaction:

    def __init__(self, sender_address, sender_private_key, recipient_address, drug_name, value,price):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.drug_name = drug_name
        self.value = value
        self.price = price

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict(self):
        return OrderedDict({'sender_address': self.sender_address,
                            'recipient_address': self.recipient_address,
                            'drug_name': self.drug_name,
                            'value': self.value,
                            'price': self.price})

# For signature we want sender private key
# we are sign transaction using private key of user
# we import 'from Crypto.Signature import PKCS1_v1_5' this library
    def sign_transaction(self):
        """
        Sign transaction with private key
        """
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))  #we are going to sign content of transaction
        return binascii.hexlify(signer.sign(h)).decode('ascii')



app = Flask(__name__)

@app.route('/')
def index():
	return render_template('./index.html')

@app.route('/make/transaction')
def make_transaction():
    return render_template('./make_transaction.html')

@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')

#binascii.hexlify will convert value into hexa decimal 
#exportKey(format='DER') will export key
@app.route('/wallet/new', methods=['GET'])
def new_wallet():
	random_gen = Crypto.Random.new().read
	private_key = RSA.generate(1024, random_gen)
	public_key = private_key.publickey()
	response = {
		'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
		'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
	}

	return jsonify(response), 200

@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
	
	sender_address = request.form['sender_address']
	sender_private_key = request.form['sender_private_key']
	recipient_address = request.form['recipient_address']
	drug_name = request.form['drug_name']
	value = request.form['amount']
	mt=0
	price = request.form['price']
	dt[str(recipient_address)]={}
	dt[str(recipient_address)]['drug_names']=drug_name
	dt[str(recipient_address)]['amounts']=value
	print(dt)
	pp=str(sender_private_key)
	for i in dt:
		if(i==pp):
			print("zala")
			if(dt[i]['drug_names']==drug_name and dt[i]['amounts']>=value):
				print("yogya check data same or not")
			else:
				response={'message':'data is not currect'}
				return jsonify(response), 406
		else:
			print("first transcation")
	transaction = Transaction(sender_address, sender_private_key, recipient_address, drug_name, value, price)

	response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction()}

	return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)
