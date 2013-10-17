package com.tlv;

import com.paymentreader.*;

public class TLVObjectSet
{
	public TLVObject[] set = new TLVObject[0];
	
	public void getTLVObjectSet(byte[] data, short offset, short leng)
	{
		//get a count of the TLV objects
		TLVObject TLV = new TLVObject();
		short i=0;
		short tOffset = offset;
		while(tOffset<(leng+offset) || leng==0)
		{
			if(TLV.getTLVObject(data,tOffset,true))
			{
				i++;
				tOffset=(short)(TLV.offset+TLV.leng);
				if(leng==0) break; //find only the first one
			}
			else
				break;
		}
		
		//create the storage for the set
		set = new TLVObject[i];
		for(i=0;i<set.length;i++)
		{
			set[i] = new TLVObject();
		}
		
		//store the set
		for(i=0;i<set.length;i++)
		{
			if(set[i].getTLVObject(data,offset,true))
			{
				offset=(short)(set[i].offset+set[i].leng);
				if(leng==0) break; //find only the first one
			}
			else
				break;
		}
	}
	
	public TLVObject getTLVObject(byte[] data, byte[]tag, short tagOffset, short tagLeng)
	{
		for(short i=0;i<set.length;i++)
		{
			//check for tag match
			if(readCard.arrayCompare(tag,tagOffset,data,set[i].tagOffset,tagLeng))
				return set[i];
		}
		return null;
	}
	
	public class TLVObject
	{
		public short tagOffset = 0;
		public short tagLeng = 0;
		public short leng = 0;
		public short offset = 0;
		
		public boolean getTLVObject(byte[] data, short TLVOffset, boolean checkLeng)
		{
			//store the tag
			while(TLVOffset<data.length)
			{
				if ((short)(data[TLVOffset]&0xFF)==0x00 || (short)(data[TLVOffset]&0xFF)==0xFF)
					TLVOffset++;
				else
					break;
			}
			tagOffset = TLVOffset;
			tagLeng = 0;
			if(TLVOffset>data.length) return false;
			while(TLVOffset<data.length)
			{
				if(((tagLeng==0) && (short)(data[TLVOffset]&0x1F) == 0x1F) ||
				   ((tagLeng>0) && (short)(data[TLVOffset]&0x80) == 0x80)	)
				{
					tagLeng++;
					TLVOffset++;
					if(TLVOffset>data.length) return false;
				}
				else
					break;
			}
			tagLeng++;
			TLVOffset++;  //increment to length bytes
			if(TLVOffset>data.length) return false;
				
			//store the length
			if((short)(data[TLVOffset]&0x80) == 0x00)
			{
				leng = (short)(data[TLVOffset]&0xFF);
				TLVOffset++;
			}
			else
			{
				if((short)(data[TLVOffset]&0x7F) == 0x01)
					leng = (short)(data[TLVOffset+1]&0xFF);
				else if((short)(data[TLVOffset]&0x7F) == 0x02)
					leng = (short)((((short)(data[TLVOffset+1]&0xFF))<<8) + (short)(data[TLVOffset+2]&0xFF));
				else 
					return false;
				TLVOffset+=(short)(data[TLVOffset]&0x7F);
				TLVOffset++;
			}
			if(TLVOffset>data.length) return false;
			//store the data offset
			offset = TLVOffset;
			if(checkLeng && (leng+offset)>data.length) return false;
			return true;
		}
	}
}

