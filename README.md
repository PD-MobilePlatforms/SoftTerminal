SoftTerminal
============

A terminal used to transact with the simply tapp cloud cards

Card Support
============
currently this terminal will read:
MasterCard PayPass
Visa Contactless
Discover Zip
American Express ExpressPay

Functionality
=============
the terminal first selects PPSE, then from there will select
the appropriate card application from the supported cards 
above

after the card has been interrogated, the resultant track 1
and track 2 data will be print out

Parameters
==========
-ck  the acquirer consumer key
-cs  the acquirer consumer secret
-at  the transaction access token
-ts  the trasaction access token secret
