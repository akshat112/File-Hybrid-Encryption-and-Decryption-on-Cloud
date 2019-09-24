from flask import Flask,redirect,url_for
from flask import request
from flask import render_template
from flask import send_file
from Cryptodome.PublicKey import RSA
import os
import sys
import zipfile
from Cryptodome import Random
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import random
from Cryptodome.Signature import PKCS1_v1_5
from werkzeug.utils import secure_filename
import webbrowser
app = Flask(__name__, static_folder='static', static_url_path='')


@app.route('/senderkeygenerate')
def sender_generate():
	return render_template("sender-key.html")

@app.route('/receiverkeygenerate')
def receive_generate():
	return render_template("receiver-key.html")

@app.route('/keygen/sender')
def sengen():
	password = request.args.get('password')
	keyPair = RSA.generate(1024)
	f = open("./static/sender/A_PrivateKey.pem", "w")
	f.write(keyPair.exportKey("PEM",password))
	f.close()
	f = open("./static/sender/A_PublicKey.pem", "w")
	f.write(str(keyPair.publickey().exportKey()))
	f.close()
	return redirect('/sengenerated')

@app.route('/keygen/receiver')
def recgen():
	password = request.args.get('password')
	keyPair = RSA.generate(1024)
	f = open("./static/receiver/B_PrivateKey.pem", "w")
	f.write(keyPair.exportKey("PEM",password))
	f.close()
	f = open("./static/receiver/B_PublicKey.pem", "w")
	f.write(str(keyPair.publickey().exportKey()))
	f.close()
	return redirect('/recgenerated')

@app.route('/sengenerated')
def sengend():
	return render_template("generated-sender.html")
@app.route('/recgenerated')
def recgend():
	return render_template("generated-receiver.html")

#download sender public key
@app.route('/dspub')
def dspub():
	return send_file('./static/sender/A_PublicKey.pem', as_attachment=True)

#download sender private key
@app.route('/dspri')
def dspri():
	return send_file('./static/sender/A_PrivateKey.pem', as_attachment=True)

#download receiver public key
@app.route('/drpub')
def drpub():
	return send_file('./static/receiver/B_PublicKey.pem', as_attachment=True)

#download receiver private key
@app.route('/drpri')
def drpri():
	return send_file('./static/receiver/B_PrivateKey.pem', as_attachment=True)

#download encrypted file
@app.route('/downenc')
def downenc():
	return send_file('./encrypted.all', as_attachment=True)

#download decrypted file
@app.route('/downdec')
def downdec():
	return send_file('./decrypted.txt', as_attachment=True)

@app.route('/error')
def error():
	return render_template('error.html')

@app.route('/signauth')
def signauth():
	return render_template('signauth.html')

UPLOAD_FOLDER = ""
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER 
@app.route('/')
def homepage():
    return render_template("home.html")
@app.route('/key')
def banana():
	return render_template("input.html")

# @app.route('/keys')
# def inp():
# 	password = request.args.get('password', 'test')
# 	keyPair = RSA.generate(1024)
# 	f = open("./static/priKey.pem", "w")
# 	f.write(keyPair.exportKey("PEM",password))
# 	f.close()
# 	f = open("./static/pubKey.pem", "w")
# 	f.write(str(keyPair.publickey().exportKey()))
# 	f.close()
# 	return redirect('/generated')
# @app.route('/generated')
# def inp1():
# 	return render_template("generated.html")
	
################################################################
@app.route('/upload/',methods = ['GET','POST'])
def upload_file():
    if request.method =='POST':
        file = request.files['file[]']
        if file:
            filename = "encrypted.txt"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
    return redirect('/key1')
@app.route('/key1')
def banana1():
	return render_template("input1.html")
@app.route('/encrypt')
def encrypt():
	# import os
	# import sys
	# import zipfile
	# from Cryptodome import Random
	# from Cryptodome.Cipher import AES, PKCS1_OAEP
	# from Cryptodome.Hash import SHA256
	# from Cryptodome.PublicKey import RSA
	# from Cryptodome.Random import random
	# from Cryptodome.Signature import PKCS1_v1_5
	password = request.args.get('password')
	file = request.args.get('file')
	# Define public and private key names for faster usage
	# Sender's private key:
	priKey = "./static/sender/A_PrivateKey.pem"
	# Receiver's public key:
	pubKey = "./static/receiver/B_PublicKey.pem"
	
	
	
	def usage():
	    print "python encipher.py ./static/<file_name>"
	    sys.exit(-1)
	
	
	def sigGenerator(priKey_fname, file, password):
	    # Opening and reading file to encrypt
	
	    f = open(file, "r")
	    buffer = f.read()
	    f.close()
	
	    # Creating hash of the file. Using SHA-256 (SHA-512 rose problems)
	
	    h = SHA256.new(buffer)
	
	    # Reading private key to sign file with
	
	    keyPair = RSA.importKey(open(priKey_fname, "r").read(), passphrase=password)
	    keySigner = PKCS1_v1_5.new(keyPair)
	
	    # Saving signature to *.sig file
	
	    f = open(file.split('.')[0] + ".sig", "w")
	    f.write(keySigner.sign(h))
	    f.close()
	
	
	def keyGenerator(pubKey_fname, file, iv):
	    # Generating 1024 random bits, and creating SHA-256 (for 32 bits compatibility with AES)
	
	    h = SHA256.new(str(random.getrandbits(1024)))
	
	    # Reading public key to encrypt AES key with
	
	    keyPair = RSA.importKey(open(pubKey_fname, "r").read())
	    keyCipher = PKCS1_OAEP.new(keyPair.publickey())
	
	    # Saving encrypted key to *.key file
	
	    f = open(file.split('.')[0] + ".key", "w")
	    f.write(iv + keyCipher.encrypt(h.digest()))
	    f.close()
	
	    # Returning generated key to encrypt file with
	
	    return h.digest()
	
	
	def encipher(keyA_fname, keyB_fname, file, password):
	    # Opening file to encrypt in binary reading mode
	
	    f = open(file, "rb")
	    buffer = f.read()
	    f.close()
	
	    # Generating file's signature (and saving it)
	
	    sigGenerator(keyA_fname, file, password)
	
	    # Generating initializing vector for AES Encryption
	
	    iv = Random.new().read(AES.block_size)
	
	    # Generating symmetric key for use (and saving it)
	
	    k = keyGenerator(keyB_fname, file, iv)
	
	    # Encrypting and saving result to *.bin file. Using CFB mode
	
	    keyCipher = AES.new(str(k), AES.MODE_CFB, iv)
	    f = open(file.split('.')[0] + ".bin", "wb")
	    f.write(keyCipher.encrypt(buffer))
	    f.close()
	
	
	def auxFilesZip(sig, key, bin):
	    # Opening file to contain all bin, sig and key files
	
	    f = zipfile.ZipFile(bin.split('.')[0] + ".all", "w")
	
	    # Writing each of the arguments to the created file
	
	    f.write(sig)
	    f.write(key)
	    f.write(bin)
	
	    # Closing the file
	
	    f.close()
	
	    # Running clean up to the bin, sig and key files
	
	    cleanUp(sig, key, bin)
	
	
	def cleanUp(sig, key, bin):
	    # Deleting each of the files generated during ciphering
	
	    os.remove(sig)
	    os.remove(key)
	    os.remove(bin)
	
	
	def checkFiles(file, pubKey, priKey):
	    # Checking for encrypting file's existence and access
	
	    if not os.path.isfile(file) or not os.access(file, os.R_OK):
	        print "Invalid file to encrypt. Aborting..."
	        sys.exit(1)
	
	    # Checking for each of the files to create existence and, in case they exist, if they are writable
	
	    else:
	        s = file.split('.')[0]
	        if os.path.isfile(s + ".sig") and not os.access(s + ".sig", os.W_OK):
				return redirect("/error")
	            # print "Can't create temporary file: *.bin. Aborting..."
	            # sys.exit(2)
	        if os.path.isfile(s + ".key") and not os.access(s + ".key", os.W_OK):
				return redirect("/error")
	            # print "Can't create temporary file: *.key. Aborting..."
	            # sys.exit(3)
	        if os.path.isfile(s + ".bin") and not os.access(s + ".bin", os.W_OK):
				return redirect("/error")
	            # print "Can't create temporary file: *.bin. Aborting..."
	            # sys.exit(4)
	        if os.path.isfile(s + ".all") and not os.access(s + ".all", os.W_OK):
				return redirect("/error")
	            # print "Can't create output file. Aborting..."
	            # sys.exit(5)
	
	    # Checking for public key's existence and access
	
	    if not os.path.isfile(pubKey) or not os.access(pubKey, os.R_OK):
			return redirect("/error")
	        # print "Invalid public key file. Aborting..."
	        # sys.exit(6)
	
	    # Checking for private key's existence and access
	
	    if not os.path.isfile(priKey) or not os.access(priKey, os.R_OK):
			return redirect("/error")
	        # print "Invalid private key file. Aborting..."
	        # sys.exit(7)
	
	
	# Gathering encrypting file name
	
	if len(sys.argv) > 2:
	    usage()
	elif len(sys.argv) == 1:
	    file = file
	else:
	    file = sys.argv[1]
	
	# Gathering names of keys
	
	if priKey == "":
	    print "Sender's private key file name:"
	    priKey = raw_input(">>> ")
	if pubKey == "":
	    print "Receiver's public key file name:"
	    pubKey = raw_input(">>> ")
	
	# Running checks to files
	
	checkFiles(file, pubKey, priKey)
	
	# Reading password if not assigned:
	
	
	    
	
	# Ciphering file (and generating all auxiliary files)
	
	encipher(priKey, pubKey, file, password)
	
	# Generating output file and clean up
	
	auxFilesZip(file.split('.')[0] + ".sig", file.split('.')[0] + ".key", file.split('.')[0] + ".bin")
	return redirect("/generated1")
@app.route('/generated1')
def inp2():
	return render_template("encrypted.html")   

########################################################################################

@app.route('/key2')
def banana2():
	return render_template("input2.html")
@app.route('/decrypt')
def decrypt():
	# Define public and private key names for faster usage
	password = request.args.get('password')
	file = request.args.get('file')
	# Sender's public key:
	pubKey = "./static/sender/A_PublicKey.pem"
	# Receiver's private key:
	priKey = "./static/receiver/B_PrivateKey.pem"
	
	
	
	def usage():
	    print "python decipher.py <file>"
	    sys.exit(-1)
	
	
	def sigVerification(pubKey_fname, file):
	    # Generating decrypted file's SHA-256
	
	    h = SHA256.new()
	    h.update(open(file, "r").read())
	
	    # Reading public key to check signature with
	
	    keyPair = RSA.importKey(open(pubKey_fname, "r").read())
	    keyVerifier = PKCS1_v1_5.new(keyPair.publickey())
	
	    # If signature is right, prints SHA-256. Otherwise states that the file is not authentic
	
	    if keyVerifier.verify(h, open(file.split('.')[0] + ".sig", "r").read()):
	        # print "The signature is authentic."
	        # print "SHA-256 -> %s" % h.hexdigest()
			webbrowser.open_new('http://localhost:5000/signauth')
			
	    else:
	        # print "The signature is not authentic."
			return redirect("/error")
			# webbrowser.open_new('http://localhost:5000/error')
	
	
	def keyReader(privKey_fname, file, password):
	    # Reading private key to decipher symmetric key used
	
	    keyPair = RSA.importKey(open(privKey_fname, "r").read(), passphrase=password)
	    keyDecipher = PKCS1_OAEP.new(keyPair)
	
	    # Reading iv and symmetric key used during encryption
	
	    f = open(file.split('.')[0] + ".key", "r")
	    iv = f.read(16)
	    k = keyDecipher.decrypt(f.read())
	
	    return k, iv
	
	
	def decipher(keyA_fname, keyB_fname, file, password):
		# Getting symmetric key used and iv value generated at encryption process

		k, iv = keyReader(keyB_fname, file, password)

		# Deciphering the initial information and saving it to file with no extension


		keyDecipher = AES.new(k, AES.MODE_CFB, iv)
		bin = open("./encrypted.bin", "rb").read()
		f = open("./decrypted.txt", "wb")
		f.write(keyDecipher.decrypt(bin))
		f.close()

		# Running a Signature verification

		sigVerification(keyA_fname, file.split('.')[0]+".txt")
	
	
	def auxFilesUnzip(all):
	    # Opening the input file
	
	    f = zipfile.ZipFile(all + ".all", "r")
	
	    # Extracting all of its files
	
	    f.extractall()
	
	
	def cleanUp(sig, key, bin, all):
	    # Removing all of the files created, except for the final deciphered file
	
	    os.remove(sig)
	    os.remove(key)
	    os.remove(bin)
	    os.remove(all)
	
	
	def checkFiles(file, pubKey, priKey, first_run):
	    # Checking for decrypting file's existence and access, keys, aux and output files
	
	    if first_run:
	        # Checking for decrypting file's existence and access
	
	        if not os.path.isfile(file + ".all") or not os.access(file + ".all", os.R_OK):
	            # print "Invalid file to decrypt. Aborting..."
				redirect("/error")
	            # sys.exit(1)
	
	        # Checking for public key's existence and access
	
	        if not os.path.isfile(pubKey) or not os.access(pubKey, os.R_OK):
	            # print "Invalid public key file. Aborting..."
				redirect("/error")
	            # sys.exit(6)
	
	        # Checking for private key's existence and access
	
	        if not os.path.isfile(priKey) or not os.access(priKey, os.R_OK):
	            # print "Invalid private key file. Aborting..."
				redirect("/error")
	            # sys.exit(7)
	
	    elif not first_run:
	        # Checking if all of the necessary files exist and are accessible
	
	        if not os.path.isfile(file + ".sig") or not os.access(file + ".sig", os.R_OK):
	            # print "Invalid *.sig file. Aborting..."
				redirect("/error")
	            # sys.exit(2)
	        if not os.path.isfile(file + ".key") or not os.access(file + ".key", os.R_OK):
	            # print "Invalid *.key file. Aborting..."
				redirect("/error")
	            # sys.exit(3)
	        if not os.path.isfile(file + ".bin") or not os.access(file + ".bin", os.R_OK):
	            # print "Invalid *.bin file. Aborting..."
				redirect("/error")
	            # sys.exit(4)
	
	        # Checking if in case of output file's existence, it is writable
	
	        if os.path.isfile(file) and not os.access(file, os.W_OK):
	            # print "Can't create output file. Aborting..."
				redirect("/error")
	            # sys.exit(5)
	
	
	# Gathering encrypting file name
	
	if len(sys.argv) > 2:
	    usage()
	elif len(sys.argv) == 1:
	    
	    file = file
	else:
	    file = sys.argv[1]
	
	# Gathering names of keys
	
	if pubKey == "":
	    print "Sender's public key file name:"
	    pubKey = raw_input(">>> ")
	if priKey == "":
	    print "Receiver's private key file name:"
	    priKey = raw_input(">>> ")
	
	file = file.split('.')[0]
	
	# Checking for *.all file and keys' files
	
	checkFiles(file, pubKey, priKey, True)
	print "Here 1"
	# Unzipping all files
	
	auxFilesUnzip(file)
	print "Here 2"
	# Checking for *.sig, *.key, *.bin files
	
	checkFiles(file, pubKey, priKey, False)
	print "Here 3"
	# Reading password if not assigne
	
	# Deciphering file
	
	
	decipher(pubKey, priKey, file, password)
	
	# Cleaning all files but the deciphered file
	
	cleanUp(file + ".sig", file + ".key", file + ".bin", file + ".all")
	return redirect("/generated2")

@app.route('/generated2')
def inp3():
	return render_template("done.html")

if __name__ == '__main__':
    app.run(host=os.getenv('IP', '0.0.0.0'),port=int(os.getenv('PORT', 5000)))