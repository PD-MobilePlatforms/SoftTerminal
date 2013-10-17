package com.expresspay;

import java.util.Random;
import com.iso.isoComm;
import com.tlv.TLVObjectSet;

public class MSD {
	
	//express pay AID
	public static byte[] AID = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x25, 0x01 };

	public class tracks
	{
		public byte[] track1;
		public byte[] track2;
	}
	
	private byte[] hex_to_ascii(byte[] hex, short offset, short leng)
	{
	  short i;
	  byte nib;
	  byte[] data = new byte[leng*2];
	  for(i=0;i<leng*2;i++)
	  {
	    if((i&0x01) == 0x01) nib=(byte)(short)((hex[offset+(i/2)])&0x0F);
	    else nib=(byte)((short)((hex[offset+(i/2)])&0xFF)>>4);
	    if(nib<0x0A) data[i]=(byte)(nib+0x30);
	    else data[i]=(byte)(nib+0x37);
	  }
	  return data;
	}

	//takes 2 bytes hex and replaces with 3 bytes dec
	private byte[] hex_to_dec(byte[] hex)
	{
		byte[] data=new byte[3];
		long num = (short)(hex[0]&0xFF)*256 + (short)(hex[1]&0xFF);
		data[0]=(byte)((byte)((((num%1000000)/100000)*16)&0xFF) +     (byte)(((num%100000)/10000)&0xFF));
		data[1]=(byte)((byte)((((num%10000)/1000)*16)&0xFF) +         (byte)(((num%1000)/100)&0xFF));
		data[2]=(byte)((byte)((((num%100)/10)*16)&0xFF) +             (byte)(((num%10)/1)&0xFF));
		return data;
	}

	//takes 3 bytes hex and replaces with 4 bytes dec
	private byte[] hex_to_dec3(byte[] hex)
	{
		byte[] data=new byte[4];
		long num = (short)(hex[0]&0xff)*65536 + (short)(hex[1]&0xff)*256 + (short)(hex[2]&0xff);
		data[0]=(byte)((byte)((((num%100000000)/10000000)*16)&0xFF) + (byte)(((num%10000000)/1000000)&0xFF));
		data[1]=(byte)((byte)((((num%1000000)/100000)*16)&0xFF) +     (byte)(((num%100000)/10000)&0xFF));
		data[2]=(byte)((byte)((((num%10000)/1000)*16)&0xFF) +         (byte)(((num%1000)/100)&0xFF));
		data[3]=(byte)((byte)((((num%100)/10)*16)&0xFF) +             (byte)(((num%10)/1)&0xFF));
		return data;
	}

	private byte[] select()
	{
		//select PayPass APDU
		byte[] data = new byte[AID.length + 6];  //header=5, footer=1
		data[0] = 0x00;
		data[1] = (byte)0xA4;
		data[2] = 0x04;
		data[3] = 0x00;
		data[4] = (byte) AID.length;
		for(byte i=0;i<AID.length;i++)
		{
			data[5+i] = AID[i];
		}
		data[5+AID.length] = 0x00;

		return isoComm.transceive(data);
	}

	private byte[] GPO(byte[] PDOL)
	{
		//GPO APDU
		byte[] data = new byte[7+PDOL.length+1]; 
		data[0] = (byte)0x80;
		data[1] = (byte)0xA8;
		data[2] = 0x00;
		data[3] = 0x00;
		data[4] = (byte)(short)((PDOL.length+2)&0xff);
		data[5] = (byte)0x83;
		data[6] = (byte)(short)(PDOL.length&0xff);
		for(short i=0;i<PDOL.length;i++)
		{
			data[7+i]=PDOL[i];
		}
		data[7+PDOL.length] = 0x00;
		return isoComm.transceive(data);
	}

	private byte[] readRecord(byte P1, byte P2)
	{
		//select PayPass APDU
		byte[] data = new byte[5];  //header=5
		data[0] = 0x00;
		data[1] = (byte)0xB2;
		data[2] = P1;
		data[3] = P2;
		data[4] = 0x00;

		return isoComm.transceive(data);
	}

	private byte[] getATC()
	{
		//select express pay APDU
		byte[] data = new byte[5];  //header=5
		data[0] = (byte)0x80;
		data[1] = (byte)0xCA;
		data[2] = (byte)0x9F;
		data[3] = 0x36;
		data[4] = 0x00;

		return isoComm.transceive(data);
	}

	private byte[] genAC(byte[] UN)
	{
		//GPO APDU
		byte[] data = new byte[5+UN.length+1]; 
		data[0] = (byte)0x80;
		data[1] = (byte)0xAE;
		data[2] = (byte)0x80;
		data[3] = 0x00;
		data[4] = (byte)(short)((UN.length)&0xff);
		for(short i=0;i<UN.length;i++)
		{
			data[5+i]=UN[i];
		}
		data[5+UN.length] = 0x00;
		return isoComm.transceive(data);
	}

	private byte[] getTLVData(byte[] tag, TLVObjectSet TLVSet, byte[] data)
	{
		com.tlv.TLVObjectSet.TLVObject TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)tag.length);
		byte[] retData;
		if(TLVMsg==null)
		{
			retData = new byte[0];
		}
		else
		{
			retData = new byte[TLVMsg.leng];
			for(short i=0; i<TLVMsg.leng; i++)
			{
				retData[i] = data[TLVMsg.offset+i];
			}
		}
		return retData;
	}

	public tracks readTracks()
	{
		
		//select AID
		byte[] data = select();
		if(data==null || data.length<2 || data[data.length-2]!=(byte)0x90 || data[data.length-1]!=(byte)0x00)
			return null;
		TLVObjectSet TLVSet = new TLVObjectSet();
		TLVSet.getTLVObjectSet(data,(short)0,(short)(data.length-2));
		byte[] tag = new byte[2];
		tag[0] = 0x6F; //FCI template
		com.tlv.TLVObjectSet.TLVObject TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
		if(TLVMsg!=null && TLVMsg.leng>0) 
		{
			TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
			tag[0] = (byte)0xA5; //FCI proprietary template
			TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
			if(TLVMsg!=null && TLVMsg.leng>0)
			{
				TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
				tag[0] = (byte)0x9F; //PDOL data
				tag[1] = (byte)0x38; //PDOL data
				TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)2);
			}
			else
				return null;
		}
		else
			return null;
		
		//GPO
		byte[] PDOL;
		if(TLVMsg==null || TLVMsg.leng<1) 
		{
			//no PDOL
			PDOL = new byte[0];
		}
		else
		{
			if(TLVMsg.leng<3 || data[TLVMsg.offset]!=(byte)0x9F || data[TLVMsg.offset+1]!=(byte)0x35 || data[TLVMsg.offset+2]!=0x01)
	        	return null;
			//PDOL
			PDOL = new byte[1];
			PDOL[0]=0x21;
		}
		data = GPO(PDOL);
		if(data==null || data.length<2 || data[data.length-2]!=(byte)0x90 || data[data.length-1]!=(byte)0x00)
			return null;
		byte[] rec;
		TLVSet = new TLVObjectSet();
		TLVSet.getTLVObjectSet(data,(short)0,(short)(data.length-2));
		tag[0] = (byte)0x80; //format 1
		TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
		if(TLVMsg!=null && TLVMsg.leng>0)
		{
			if((data[TLVMsg.offset]&0x83)!=0 || (data[TLVMsg.offset+1]&0xFF)!=0)
				return null;
			if(((TLVMsg.leng-2)%4)!=0)
				return null;
			rec = new byte[TLVMsg.leng-2];
			for(short i=0;i<rec.length;i++)
			{
				rec[i]=data[TLVMsg.offset+2+i];
			}
		}
		else
			return null;
		short i=0;
		byte[] T2 = new byte[0];
		short T2_len=0;
		byte[] NAME = new byte[0];
		byte[] EXP = new byte[0];
		byte[] EFF = new byte[0];
		byte[] SC = new byte[0];
		byte[] PAN = new byte[0];
		byte[] PANSQ = new byte[0];
		byte[] TRM = new byte[0];
		byte[] IAC_den = new byte[0];
		byte[] AVN = new byte[0];
		com.tlv.TLVObjectSet.TLVObject TLVMsg2 = null;
		byte[] data2 = new byte[0];;
		while(i<rec.length)
		{
			if(((short)(rec[i+2]&0xff)-(short)(rec[i+1]&0xff))<0)
				return null;
			for(short j=0;j<((short)(rec[i+2]&0xff)-(short)(rec[i+1]&0xff)+1);j++)
			{
				//read record
				data = readRecord((byte)(((short)(rec[i+1]&0xff) + j)&0xff),(byte)((0x04|rec[i])&0xff));
				if(data==null || data.length<2 || data[data.length-2]!=(byte)0x90 || data[data.length-1]!=(byte)0x00)
					return null;
				TLVSet = new TLVObjectSet();
				TLVSet.getTLVObjectSet(data,(short)0,(short)(data.length-2));
				tag[0] = (byte)0x70; //MSG
				TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
				if(TLVMsg!=null && TLVMsg.leng>0)
				{
					TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
					//get TAG data
					tag[0] = (byte)0x57; //T2
					TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
					if(TLVMsg!=null && TLVMsg.leng>0)
					{
						T2 = hex_to_ascii(data,TLVMsg.offset,TLVMsg.leng);
						short k;
						for(k=0;k<T2.length;k++)
						{
							if(T2[k]=='D' || T2[k]=='d')
							{
								T2[k]='=';
								if((T2.length-k+1)>7)
								{
									if(SC.length==0)
									{
										SC = new byte[3];
										SC[0]=T2[k+5];
										SC[1]=T2[k+6];
										SC[2]=T2[k+7];
									}
								}
							}
							if(T2[k]=='F' || T2[k]=='f')
							{
								break;
							}
						}
						T2_len = k;
					}
					tag[0]=(byte)0x5F; //NAME
					tag[1]=(byte)0x20; //NAME
					byte[] tmp = getTLVData(tag,TLVSet,data);
					if(tmp.length>0)
						NAME = tmp;
					tag[0]=(byte)0x5F; //EXP
					tag[1]=(byte)0x24; //EXP
					tmp = getTLVData(tag,TLVSet,data);
					if(tmp.length>0)
						EXP = tmp;
					tag[0]=(byte)0x5F; //EFF
					tag[1]=(byte)0x25; //EFF
					tmp = getTLVData(tag,TLVSet,data);
					if(tmp.length>0)
						EFF = tmp;
					byte[] tag1 = new byte[1];
					tag1[0]=(byte)0x5A; //PAN
					tmp = getTLVData(tag1,TLVSet,data);
					if(tmp.length>0)
						PAN = tmp;
					tag[0]=(byte)0x5F; //PANSQ
					tag[1]=(byte)0x25; //PANSQ
					tmp = getTLVData(tag,TLVSet,data);
					if(tmp.length>0)
						PANSQ = tmp;
					tag1[0]=(byte)0x8C; //TRM
					TLVMsg = TLVSet.getTLVObject(data, tag1, (short)0, (short)1);
					if(TLVMsg!=null && TLVMsg.leng>0)
					{
						TLVMsg2 = TLVMsg;
						data2 = data;
						TRM = new byte[TLVMsg.leng];
						for(short k=0;k<TLVMsg.leng;k++)
							TRM[k] = data[TLVMsg.offset+k];
					}
					tag[0]=(byte)0x9F; //IAC_den
					tag[1]=(byte)0x0E; //IAC_den
					tmp = getTLVData(tag,TLVSet,data);
					if(tmp.length>0)
						IAC_den = tmp;
					tag[0]=(byte)0x9F; //AVN
					tag[1]=(byte)0x08; //AVN
					tmp = getTLVData(tag,TLVSet,data);
					if(tmp.length>0)
						AVN = tmp;
				}
				else
					return null;
			}
			i+=4;
		}
		if(T2_len==0 || PAN.length==0 || TRM.length==0 || PANSQ.length==0 ||
				EFF.length==0 || EXP.length==0 || NAME.length==0 || SC.length==0)
			return null;
		
		//get ATC
		data = getATC();
		if(data==null || data.length<2 || data[data.length-2]!=(byte)0x90 || data[data.length-1]!=(byte)0x00)
			return null;
		TLVSet = new TLVObjectSet();
		TLVSet.getTLVObjectSet(data,(short)0,(short)(data.length-2));
		tag[0] = (byte)0x9F; //message
		tag[1] = (byte)0x36; //message
		TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)2);
		if(TLVMsg==null || TLVMsg.leng!=2) 
			return null;
		byte[] ATC = new byte[2];
		ATC[0]=data[TLVMsg.offset];
		ATC[1]=data[TLVMsg.offset+1];
		
		if(IAC_den.length>0)
		{
			if((short)(IAC_den[0]&0x80)>0)
				return null;  //no auth
			if((short)(IAC_den[1]&0x80)>0 && (AVN.length!=2 || AVN[0]!=0x00 || AVN[1]!=0x01))
				return null;  //different versions
		}
		
		//generate UN
		if(EFF.length<2)
			return null;
		byte[] UN = new byte[4];
		Random generator = new Random();
		short r = (short)(generator.nextInt()&0x00007FFF);
		r=(short)(r%1201);
		UN[0]=0x00;
		UN[1]=0x00;
	    short k = (short)((short)((EFF[0]>>4)*10+(EFF[0]&0xF))-(short)(r/12));
		if(k<0) k+=100;
		UN[2] = (byte)(((k/10)<<4) + (k%10));
		k = (short)((short)((EFF[1]>>4)*10+(EFF[1]&0xF))-(short)(r%12));
		if(k<0) k+=100;
		UN[3] = (byte)(((k/10)<<4) + (k%10));
		
		//generate AC
		byte[] UN2 = new byte[1];
		if(TLVMsg2!=null && TLVMsg2.getTLVObject(data2, TLVMsg2.offset, false))
		{
			if(TLVMsg2.tagLeng==2 && 
					(byte)data2[TLVMsg2.tagOffset] == (byte)0x9F &&
					(byte)data2[TLVMsg2.tagOffset+1] == (byte)0x37)
			{
				UN2 = new byte[TLVMsg2.leng];
				for(short j=0;j<UN2.length;j++)
				{
			  		if(UN2.length-j>UN.length) UN2[j]=0x00;  
			  		else UN2[j]=UN[UN.length-(UN2.length-j)];
				}
			}
			else
			{
				UN2[0] = 0x00;
			}
		}
		else
		{
			UN2[0] = 0x00;
		}
		data = genAC(UN2);
		if(data==null || data.length<2 || data[data.length-2]!=(byte)0x90 || data[data.length-1]!=(byte)0x00)
			return null;
		TLVSet = new TLVObjectSet();
		TLVSet.getTLVObjectSet(data,(short)0,(short)(data.length-2));
		tag[0] = (byte)0x80; //format 1
		TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
		if(TLVMsg.leng!=0x12)
			return null;
		//check ATC
		if(data[TLVMsg.offset+1]!=ATC[0] || data[TLVMsg.offset+2]!=ATC[1])
		    return null;  //ATC's don't match
		//check AC
		if((data[TLVMsg.offset]&0xC0)==0x00)
		    return null;  //no TC or ARQC
		if(data[TLVMsg.offset+11]!=0x06)
		    return null;  //if this is not 6 abort
		byte[] AC = new byte[3];
		AC[0] = data[TLVMsg.offset+8];
		AC[1] = data[TLVMsg.offset+9];
		AC[2] = data[TLVMsg.offset+10];
		AC = hex_to_dec3(AC);
		
		//build track data
		PAN = hex_to_ascii(PAN,(short)0,(short)PAN.length);
		if(PAN.length<1)
			return null;
		short PAN_len = (short)PAN.length;
		if(PAN[PAN.length-1]=='f' || PAN[PAN.length-1]=='F')
		{
			PAN_len--;
		}
		ATC = hex_to_dec(ATC);
		ATC = hex_to_ascii(ATC,(short)0,(short)ATC.length);
		byte[] tmp = new byte[ATC.length-3];
		for(i=0;i<ATC.length-3;i++)
		{
			tmp[i] = ATC[i+3];
		}
		ATC=tmp;
		EXP = hex_to_ascii(EXP,(short)0,(short)EXP.length);
		UN = hex_to_ascii(UN,(short)2,(short)(UN.length-2));
		AC = hex_to_ascii(AC,(short)1,(short)3);
		byte[] tmp2 = new byte[AC.length-1];
		for(i=0;i<AC.length-1;i++)
		{
			tmp2[i] = AC[i+1];
		}
		AC=tmp2;
				
		tracks tracks = new tracks();
		tracks.track1 = new byte[1 + 1 + PAN_len + 1 + 23 + ATC.length + 1 + EXP.length + SC.length + UN.length + AC.length + 1 + 1];
		short index=0;
		tracks.track1[index++] = '%';
		tracks.track1[index++] = 'B';
		for(i=0;i<PAN_len;i++)
			tracks.track1[index++] = PAN[i];
		tracks.track1[index++] = '^';
		for(i=0;i<23;i++)
		{  	
			if(i>=NAME.length) tracks.track1[index++] = ' ';
			else tracks.track1[index++] = NAME[i];
		}
		for(i=0;i<ATC.length;i++)
			tracks.track1[index++] = ATC[i];
		tracks.track1[index++] = '^';
		for(i=0;i<EXP.length;i++)
			tracks.track1[index++] = EXP[i];
		for(i=0;i<SC.length;i++)
			tracks.track1[index++] = SC[i];
		for(i=0;i<UN.length;i++)
			tracks.track1[index++] = UN[i];
		for(i=0;i<AC.length;i++)
			tracks.track1[index++] = AC[i];
		tracks.track1[index++] = '?';
	    byte LRC = 0x00;
	    for(short j=0;j<index;j++)
	    {
	    	LRC = (byte)((LRC+tracks.track1[j])&0xFF);	
	    }
	    LRC = (byte)(((LRC^0xFF)+1)&0xFF);
		tracks.track1[index]=LRC;

		tracks.track2 = new byte[1 + T2_len + 1 + 1];
		index=0;
		tracks.track2[index++] = ';';
		for(i=0;i<T2_len;i++) 
			tracks.track2[index++] = T2[i];
		tracks.track2[index++] = '?';
		short j = 0;
		for(i=0;i<T2_len;i++)
		{
		  	if(j>0)
		  	{
		  	  if(j==8)
		  	  {
		  		  for(k=0;k<UN.length;k++)
		  			  tracks.track2[i+1+k] = UN[k]; //UN
		  	  }
		  	  if(j==12)
		  	  {
		  		  for(k=0;k<AC.length;k++)
		  			  tracks.track2[i+1+k] = AC[k]; //AC
		  	  }
		  	  if(j==17)
		  	  {
		  		  for(k=0;k<ATC.length;k++)
		  			  tracks.track2[i+1+k] = ATC[k]; //ATC
		  	  }
		  	  j++;
		  	}
		  	if(tracks.track2[i+1]=='=') j=1;
		}
	    LRC = 0x00;
	    for(j=0;j<tracks.track2.length-1;j++)
	    {
	    	LRC = (byte)((LRC+tracks.track2[j])&0xFF);	
	    }
	    LRC = (byte)(((LRC^0xFF)+1)&0xFF);
		tracks.track2[tracks.track2.length-1]=LRC;
		
		return tracks;
	}
}
