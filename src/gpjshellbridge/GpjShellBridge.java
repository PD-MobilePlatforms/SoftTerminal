package gpjshellbridge;

import java.io.IOException;

import com.paymentreader.readCard;

import oauth.signpost.OAuthConsumer;
import oauth.signpost.commonshttp.CommonsHttpOAuthConsumer;

public class GpjShellBridge {

	public static RemoteCardConnection connection;
	
	public static byte[] transceive(byte[] data)
	{
		//transact now
		TransceiveData tData = new TransceiveData(TransceiveData.DEVICE_CHANNEL);
		tData.setTimeout((short)15000);
		tData.packApdu(data,true);
		try {
			connection.transceive(tData);
		} catch (IOException e) {
			return null;
		}
		return tData.getNextResponse();
	}
	
	public static void main(String[] args) {
		
    	String ck = null;
    	String cs = null;
    	String at = null;
    	String ts = null;
    	
		for(short i=0;i<args.length;i++)
		{
			switch(args[i])
			{
			case "--help":
			case "-h":
				/*java -jar SoftTerminal.jar -ck L5cx5gHqvaNIKUMAbIm0I5zLEfTXJucMGxrLrvaT -cs WSoq3n7Nwm4wmaLCfsAL3jaPBcxMg6MuyeDHZpHa -at ngEKtsdOyGCnSkhiOINjtm5UQubd3I665npZwYdH -ts A2cVVFbtAwbGQncKvBNBcOPIZLdM8jHktV8vR2sD

				the params to SoftTerminal are as follows:
				-ck  the acquirer consumer key
				-cs  the acquirer consumer secret
				-at  the transaction access token
				-ts  the trasaction access token secret*/

	    		System.out.println("Usage:");
	    		System.out.println("java -jar SoftTerm.jar -ck consumer_key -cs consumer_secreet -at access_token -ts access_secret");
	    		System.out.println("-ck  the issuer consumer key");
	    		System.out.println("-cs  the issuer consumer secret");
	    		System.out.println("-at  the card access token");
	    		System.out.println("-ts  the card access token secret");
	    		System.exit(-1);
				return;
			case "-ck":
			case "--consumer_key":
				i++;
				if(i<args.length)
					ck = args[i];
				break;
			case "-cs":
			case "--consumer_secret":
				i++;
				if(i<args.length)
					cs = args[i];
				break;
			case "-at":
			case "--access_token":
				i++;
				if(i<args.length)
					at = args[i];
				break;
			case "-ts":
			case "--token_secret":
				i++;
				if(i<args.length)
					ts = args[i];
				break;
			default:
				break;
			}
		}

		//arg check
    	if(ts==null)
    	{
    		System.out.println("-ts token secret must be assigned");
    		System.exit(-1);
			return;
    	}
       	if(cs==null)
    	{
    		System.out.println("-cs consumer secret must be assigned");
    		System.exit(-1);
			return;
    	}
       	if(ck==null)
    	{
    		System.out.println("-ck consumer key must be assigned");
    		System.exit(-1);
			return;
    	}
       	if(at==null)
    	{
    		System.out.println("-at access token must be assigned");
    		System.exit(-1);
			return;
    	}

    	OAuthConsumer consumer = new CommonsHttpOAuthConsumer(ck, cs);
		consumer.setTokenWithSecret(at, ts);

		connection = null;
		try{
			connection = new RemoteCardConnection(consumer);
		} catch(IOException e){
    		System.out.println(e.getMessage());
    		System.exit(-1);
			return;
		}
		
	    //System.out.println("Connecting to SimplyTapp card...");
	    try {
			connection.connect();
			//System.out.println("Connected");
		} catch (IOException e) {
    		System.out.println(e.getMessage());
    		System.exit(-1);
			return;
		}

	    //ATR
		TransceiveData tData = null;
		tData = new TransceiveData(TransceiveData.DEVICE_CHANNEL);
		tData.setTimeout((short)15000);
		tData.packCardReset(true);
		try {
			connection.transceive(tData);
		} catch (IOException e) {
			return;
		}
		byte[] data = tData.getNextResponse();
		if(data==null)
		{
			return;
		}

		String tracks = new readCard().read();
		if(tracks!=null)
			System.out.println(tracks);
		else
			System.out.println("card type not supported");
		try {
			connection.disconnect();
		} catch (IOException e) {
		}
    }
}
