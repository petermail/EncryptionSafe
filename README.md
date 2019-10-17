# EncryptionSafe
This is open source project for safe encryption of data like keys and secrets that can not use asymmetric cypher because we require to decypher them and therefore we require symmetric encryption. It can be used for storing secret data like Bitcoin private keys or keys to interact with exchange APIs.
The solution contains two project. One is console application that only demonstrates how to use classes in your own project. The other is WPF application that can be used itself for holding secret information.

## How it works?
1. The application requires initialization phase which calculates how many hashes your computer can calculate in a minute.
2. User's password is than hashed repeatedly for about one minute (based on count from initialization phase).
3. The resulting hash is than used as a password for symetric encryption of dictionary with encrypted data.
4. Each record in encrypted dictionary is decrypted by the hashed password from previous step with inidividual salt (random bytes) and it is still few times hashed again.

## WHYs?
1. We need to know how many cycles of hasing your password we can do in a minute. It also means that this number is necessary for decryption of your data.
2. Hashing a password before using it will create new much stronger password which is significantly longer with random distribution of different characters and digits. It is impossible for any attacker to guess the correct hash because for SHA256 there is about 10^77 combinations. The weak point is your original password and it's security can be increased by repeated hashing. This way any attacker will be able to try only 1 candidate for your password instead of many thousands or millions. 
4. Since each record has its own password, even same data will have different encrypted form.

## How safe is this process?
* Let's consider we have 30 combinations for each one character of a password. It means that password with 4 characters has 810 000 combinations. Regular computer shoud be able to calculate about 2 million hashes in a minute. It means that 1 minute of password hasing gives you about 4 additional character to your password. If you wished to increase your security more than just 4 additional characters, you will need to increase your hashing time exponentionaly because additional characters increase password security also exponentionaly. Equivalent of 5 characters will require about half an hour, 6 characters 6 hours and 7 characters more than 8 days.
* You can check security of a regular password at sites like https://howsecureismypassword.net/

## How to use it?
1. Wait until the initialization is finished. It should take about one minute.
2. Set your secure password and click button "Encrypt".
	* Your password hash is calculating, it will take one minute to finish then the application will unlock.
	* If you specified wrong password, you can click "Stop" and try again.
3. You can add new record at the bottom of the application. You can use 3 fields, "display" is not encrypted while "key" and "secret" are both independently encrypted.
![Application printscreen.](https://raw.githubusercontent.com/petermail/EncryptionSafe/master/Info/EncryptionSafe.png)
4. You will see your data still partially encrypted so you still need to click on the button "Decrypt" on the same row to see data in open format.
5. The button from step 4 will allow you to "Encrypt" the selected row after you no longer need to see them in open format.
6. The button from step 2 will allow you to "Encrypt" all the data and then you will need to go to step 2 in order to do any other action.
