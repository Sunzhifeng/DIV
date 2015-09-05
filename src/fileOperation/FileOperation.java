package fileOperation;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

import java.io.*;
import java.math.BigInteger;
import java.net.URI;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Scanner;

import org.apache.commons.codec.binary.Hex;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;

import tool.FileIO;
import tool.StdOut;
import IHT.IndexHashTable.Item;

import com.sun.corba.se.impl.ior.WireObjectKeyTemplate;
/**
 * �û����ض��ļ����д������
 * @author MichaelSun
 * @version 2.0
 * @date 2015.01.08
 */
public class FileOperation {

	public static final int K=1024;
	public static final int M=1024*1024;
	public static final String DO="d:/fileVerify/DO.txt";
	public static final String CSP="d:/fileVerify/CSP.txt";
	public static final String Ver="d:/fileVerify/Ver.txt";
	public static final String PUBLICINFOR="d:/fileVerify/public.txt";
	public static final String BLOCKTAG="d:/fileVerify/blockTag.txt";
	public static final String IHT="d:/fileVerify/iht.txt";
	public static final String FILEBLOCK="d:/fileVerify/fileBlock.txt";
	public static final String FILESECTOR="d:/fileVerify/fileSector.txt";

	
	public static void saveListElementArray(String fileName, List<Element[]> content) throws IOException {
		int size=content.size();
		// ��һ����������ļ���������д��ʽ
		PrintWriter out = new PrintWriter(fileName);
		for(int i=0;i<size;i++){
			Element []data=content.get(i);
			int length=data.length;
			for(int j=0;j<length;j++){
				out.println(data[j].toBigInteger());			
			}
			
		}
		out.close();
	}

	public static void saveElementArray(String fileName,Element[] a ) throws FileNotFoundException {
		PrintWriter out = new PrintWriter(fileName);		
		for(int i=0;i<a.length;i++){
			out.println(a[i]);			
		}
		out.close();
	}
	public static void saveItemArray(String fileName,Item[] item) throws FileNotFoundException{
		int length = item.length;	
		PrintWriter out =new PrintWriter(fileName);
		for(int i=0;i<length;i++){
			out.println(item[i].toString());
		}
		out.close();
	}

	/**
	 * ��key-value����ʽ����map��������
	 * @param fileName 	 	�����ļ�·��
	 * @param map		 	 Ҫ�����map����
	 * @throws IOException
	 */
	public static void saveMap(String fileName,Map<String,String>map)throws IOException{
		if(map.isEmpty()){
			StdOut.println(" empty!");
			return;
		}
		PrintWriter out =new PrintWriter(fileName);					
		Iterator it = map.entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry entry = (Map.Entry) it.next();
			String key = (String)entry.getKey();
			String value = (String)entry.getValue();			
			out.println(key+" "+value);			
		}		
		out.close();
	}

	/**
	 * ��ȡ�ļ�����
	 * @param filePath
	 * @param blockSize ��KΪ��λ
	 * @return
	 * @throws IOException 
	 */
	public static int blockNumbersOfFile(String filePath,int blockSize) throws IOException{

		File file = new File(filePath);		
		long fileLength = file.length();
		long number=fileLength/(K*blockSize);
		long remain=fileLength%(K*blockSize);		
		return (int)(remain==0?number:number+1);
	}

	//ָ�����ݰ������ٿ�
	public static int blockNumbersOfData(byte[]data,int blockSizeK) throws IOException{
		long dataLength=data.length;		
		long number=dataLength/(blockSizeK);
		long remain=dataLength%(blockSizeK);		
		return (int)(remain==0?number:number+1);
	}
	/**
	 * 
	 * @param fileSizeK	�ļ���СKB
	 * @param s			ÿ�����
	 * @param sectorSize�δ�С
	 * @return 			�ļ�����
	 */
	public static int  fileBlocks(int fileSizeK,int s,int sectorSize){
		int blockSizeK=(s*sectorSize/1000);
		int fileBlocks=(int)fileSizeK/blockSizeK;
		long remain=fileSizeK%blockSizeK;		
		fileBlocks=remain>0?fileBlocks+1:fileBlocks;
		return fileBlocks;
	}
	/**
	 * ���ļ����鴦���õ���Ӧ������Ԫ�ؼ���
	 * @param filePath  Ԥ�����ļ�·��
	 * @param blockSize �߼��ֿ��С
	 * @param r 		������
	 * @return          ���п�ӳ������Ԫ�ؼ���
	 * @throws IOException
	 */
	public static Element[] preProcessFile(String filePath,int blockSize,Field r) throws IOException{
		int blockSizeK=blockSize*K;
		int fileBlocks=blockNumbersOfFile(filePath, blockSize);
		RandomAccessFile in = new RandomAccessFile(filePath, "r");
		byte[] blockBuff=new byte[blockSizeK];//����Ĵ�С�պ�����С���			

		Element [] pdata=new Element[fileBlocks];			
		int remainBytes;//���һ�����⴦��
		//������Բ�ȡ���̲߳��д���������Ԫ�ء���mapreduce��˼�룩		
		for(int i=0;i<fileBlocks-1;i++){//����ǰfileBlocks-1��			
			in.read(blockBuff);			
			pdata[i]=r.newElementFromHash(blockBuff,0,blockSizeK);//�����ݽ���������.����ʹ��hash���ٶ���������Ҳ������newElementFromBytes
			//pdata[i]=r.newElementFromBytes(blockBuff);//�����ݽ���������.����ʹ��hash���ٶ���������Ҳ������newElementFromBytes
		}
		remainBytes=in.read(blockBuff);
		in.close();
		if(remainBytes==blockSizeK){
			pdata[fileBlocks-1]=r.newElementFromHash(blockBuff,0,blockSizeK);
		}else{//���һ����ܲ����������⴦��,����0���
			for(int k=remainBytes;k<blockBuff.length;k++){
				blockBuff[k]=0;			
			}
			pdata[fileBlocks-1]=r.newElementFromHash(blockBuff,0,blockSizeK);			
			System.out.print("�����С��"+remainBytes);
		}		
		return pdata;
	}
	/**
	 * ���ļ����зֿ���ֶ�Ԥ����
	 * @param filePath		�ļ���
	 * @param blockSize		���С
	 * @param s				ÿ��Ķ���
	 * @param sectorSize	�δ�С
	 * @param r				��������
	 * @return				n���ļ��鼰�ֶ���Ϣ����
	 * @throws IOException
	 */
	//���ڲ�����32M���ļ����԰��˷�������
	public static Map<String,Object> preProcessFile(String filePath,int blockSize,int s,int sectorSize,Field r) throws IOException{
		int blockSizeK=blockSize*K;
		int fileBlocks=blockNumbersOfFile(filePath, blockSize);
		RandomAccessFile in = new RandomAccessFile(filePath, "r");

		byte[] blockBuff;//����Ĵ�С�պ�����С���		
		Element [] pdata=new Element[fileBlocks];//��Ԫ����Ϣ			
		List<Element[]> nSectors=new ArrayList<Element[]>(fileBlocks);//��Ԫ����Ϣ	

		//������Բ�ȡ���̲߳��д���������Ԫ�ء���mapreduce��˼�룩		
		for(int i=0;i<fileBlocks-1;i++){//����ǰfileBlocks-1��
			blockBuff=new byte[blockSizeK];
			in.read(blockBuff,0,blockBuff.length);			
			pdata[i]=r.newElementFromBytes(blockBuff);//�����ݽ���������.����ʹ��hash���ٶ���������Ҳ������newElementFromBytes
			nSectors.add(preProcessBlock(s, blockBuff, sectorSize, r));//��i��ķֶ���Ϣ�ӵ�sectors��
		}
		blockBuff=new byte[blockSizeK];
		int remainBytes=in.read(blockBuff);	
		if(remainBytes==blockSizeK){//���һ�����⴦��
			pdata[fileBlocks-1]=r.newElementFromBytes(blockBuff);
			nSectors.add(preProcessBlock(s, blockBuff, sectorSize, r));
		}else{//���һ����ܲ����������⴦��,����0���
			for(int k=remainBytes;k<blockBuff.length;k++){
				blockBuff[k]=0;			
			}
			pdata[fileBlocks-1]=r.newElementFromBytes(blockBuff);	
			nSectors.add(preProcessBlock(s, blockBuff, sectorSize, r));
		}
	
			in.close();
		//����鼰����Ϣ���ļ�
	   //saveElementArray(FILEBLOCK, pdata);
	//	saveListElementArray(FILESECTOR, nSectors);
		
		Map<String,Object> blockSector=new HashMap<String,Object>(2);
		blockSector.put("pdata", pdata);
		blockSector.put("nSectors", nSectors);
		return blockSector;
	}
	
	//���ָ���鼰������
	public static Map<String,Object> preProcessFile(String filePath,int []blockNums,int blockSize,int s,int sectorSize,Field r) throws IOException{
		int blockSizeK=blockSize*K;
		//int fileBlocks=blockNumbersOfFile(filePath, blockSize);
		
		RandomAccessFile in = new RandomAccessFile(filePath, "r");

		byte[] blockBuff;//����Ĵ�С�պ�����С���		
		Element [] cpdata=new Element[blockNums.length];//��Ԫ����Ϣ			
		List<Element[]> cSectors=new ArrayList<Element[]>(blockNums.length);//��Ԫ����Ϣ	

		//������Բ�ȡ���̲߳��д���������Ԫ�ء���mapreduce��˼�룩		
		for(int i=0;i<blockNums.length;i++){//����ǰfileBlocks-1��
			blockBuff=new byte[blockSizeK];
			in.seek((blockNums[i]-1)*blockSizeK);
			in.read(blockBuff,0,blockBuff.length);			
			cpdata[i]=r.newElementFromBytes(blockBuff);//�����ݽ���������.����ʹ��hash���ٶ���������Ҳ������newElementFromBytes
			cSectors.add(preProcessBlock(s, blockBuff, sectorSize, r));//��i��ķֶ���Ϣ�ӵ�sectors��
		}
		
		in.close();	
		
		Map<String,Object> blockSector=new HashMap<String,Object>(2);
		blockSector.put("cpdata", cpdata);
		blockSector.put("cSectors", cSectors);
		StdOut.println(cSectors);
		return blockSector;
	}
	//���c���ļ����ǩ
	public static List<Element> cBlockTags(String filePath,int []blockNum,Pairing p) throws Exception{
		List<String> cBlocktags=FileIO.readFileByLines(filePath,blockNum);
		List<Element> result=new ArrayList<Element>(cBlocktags.size());
		for(int i=0;i<cBlocktags.size();i++){
			result.add(stringToElement(cBlocktags.get(i),p));
		}
		return result;
	}
	public static Element stringToElement(String s,Pairing p){
		StdOut.println("tag"+s);
		 Element e=p.getG1().newElementFromBytes(s.getBytes());
		StdOut.println(new BigInteger(s.getBytes()));
		 return e;
	}
	
	//���c��������ϣ����
	public static List<Item> cIHTItem(String filePath,int[]blockNum,Field r) throws Exception{
		List<String> cIhtItem=FileIO.readFileByLines(filePath,blockNum);
		List<Item> result=new ArrayList<Item>(10);
		for(int i=0;i<cIhtItem.size();i++){
			result.add(StringToItem(cIhtItem.get(i),r));
		}
		
		return result;
	}
	
	public static Item StringToItem(String s,Field r){
		StdOut.println("item"+s);
		String[] sp=s.split(" ");
		return new Item(Integer.valueOf(sp[0]),
				Integer.valueOf(sp[1]),
				Integer.valueOf(sp[2]),
				r.newElementFromBytes(sp[3].getBytes()),r.newElementFromBytes(sp[4].getBytes()));
	}
	//���ļ��������32M����������
	public static void preProcessLargeFile(String filePath,int blockSize,int s,int sectorSize,Field r) throws FileNotFoundException, IOException {  	       
		int blockSizeK=blockSize*K;
		File file = new File(filePath);
		long fileLength=file.length();//�ļ����ܳ���
		int length=0x4000000;//64M��ÿ�ζ����ڴ��������
		int count=(int)(fileLength/length);//�����ٴ�
		int remain=(int)fileLength%length;		
		count=(remain==0?count:count+1);

		FileChannel fc=new RandomAccessFile(file, "r").getChannel();
		int blockRemain=0;//64M���ݳ����ļ����С���µ��ֽ���
		for(int i=0;i<count;i++){			
			int start=i*length-blockRemain;//ÿ��ӳ�����ʼλ��
			//StdOut.println(start);
			MappedByteBuffer inputBuffer;
			//�ڴ�ӳ���ļ�������
			if (fileLength - start >= length){
				inputBuffer = fc.map(FileChannel.MapMode.READ_ONLY, start,length);// ��ȡ64M
			}else{
				inputBuffer = fc.map(FileChannel.MapMode.READ_ONLY, start,fileLength-start);// ��ȡ���ļ�  
			}

			int buffSize=16*blockSizeK;	//�������������16���鲻���ܴ���64M	
			byte[] blocksBuff = new byte[buffSize];// ÿ�δ���16�����С����  	
			for (int offset = 0; offset < length; offset += buffSize) {  
				if (length - offset >= buffSize) { 				
					inputBuffer.get(blocksBuff); 
					// ���õ���16�����ݽ��м��㣻  
					preProcessData(blocksBuff, blockSizeK, s, sectorSize, r);
				} else {  //���һ�鲻��buffsize��С�����⴦��		
					blockRemain=length-offset;//ʣ�ಿ�����¶�ȡ�´δ���

				}  
			}
		}
		fc.close();

	}

	//��һ�����ݽ��зֿ���ֶδ���,û�в�����䣬data��һ���ǿ��С��������
	private static Map<String,Object> preProcessData(byte[] data,int blockSizeK,int s,int sectorSize,Field r) throws IOException{
		int dataBlocks=blockNumbersOfData(data, blockSizeK);		
		int remain=data.length-(dataBlocks-1)*blockSizeK;//���һ����ֽ���

		Element [] pdata=new Element[dataBlocks];//��Ԫ����Ϣ			
		List<Element[]> nSectors=new ArrayList<Element[]>(dataBlocks);//��Ԫ����Ϣ	
		byte[] blockBuff;

		//������Բ�ȡ���̲߳��д���������Ԫ�ء���mapreduce��˼�룩		
		for(int i=0;i<dataBlocks-1;i++){//����ǰfileBlocks-1��
			blockBuff=subByteArray(data, i*blockSizeK, blockSizeK);
			pdata[i]=r.newElementFromHash(blockBuff,0,blockSizeK);//�����ݽ���������.����ʹ��hash���ٶ���������Ҳ������newElementFromBytes
			nSectors.add(preProcessBlock(s, blockBuff, sectorSize, r));//��i��ķֶ���Ϣ�ӵ�sectors��
		}
		blockBuff=new byte[blockSizeK];

		if(remain==blockSizeK)//�������һ��			
			subByteArray(data, (dataBlocks-1)*blockSizeK, blockSizeK,blockBuff);
		else
			subByteArray(data, (dataBlocks-1)*blockSizeK, remain,blockBuff);

		pdata[dataBlocks-1]=r.newElementFromHash(blockBuff,0,blockSizeK);
		nSectors.add(preProcessBlock(s, blockBuff, sectorSize, r));
		//������Ϣ���ļ�
		FileIO.appendElementArray(FILEBLOCK, pdata);	
		FileIO.appendListElementArray(FILESECTOR, nSectors);
		Map<String,Object> blockSector=new HashMap<String,Object>(2);
		blockSector.put("pdata", pdata);
		blockSector.put("nSectors", nSectors);
		return blockSector;
	}
	
	/**
	 * �Կ���зֶδ���
	 * @param s 			����
	 * @param blockData 	������
	 * @param sectorSize 	�δ�С
	 * @param r 			������
	 * @return 				s����Ԫ��	
	 */
	public static Element[] preProcessBlock(int s,byte[] blockData,int sectorSize,Field r){
		Element[] sectorNums=new Element[s];		
		for(int i=0;i<s;i++){
			byte[] buff=subByteArray(blockData,i*sectorSize,sectorSize);
			//���ڷֶβ���hash�ķ�ʽ
			sectorNums[i]=(r.newElementFromBytes(buff));			
		}
		return sectorNums;
	}
	/**
	 * ����������ָ����Χ�ڵ�Ԫ��
	 * @param a			��������
	 * @param offset	Ҫ����Ԫ�ص���ʼ���
	 * @param len		Ҫ����Ԫ�ص���ֹ���
	 * @return
	 */
	public static byte [] subByteArray(byte []a,int offset,int len){
		int aLength=a.length;
		if(aLength-offset<len)
			return null;	
		byte [] result=new byte[len];
		for(int i=0;i<len;i++){
			result[i]=a[offset+i];
		}

		return result;
	}
	public static void subByteArray(byte[] from,int offset,int len,byte[]to){
		int fromLength=from.length;
		if(fromLength-offset<len){
			System.out.println("��ȡ��ΧԽ�磡��");
			return;
		}
		for(int i=0;i<len;i++){
			to[i]=from[offset+i];
		}
	}
	//Ĭ�����0,�ֽ�����Ԫ�ص�Ĭ��ֵΪ0
	private static void fillOutZero(byte[]data,int offset,int len){		
		for(int i=0;i<len;i++){
			data[offset+i]=0;
		}
	}
	

	public static void clearUpFile(String configPath) throws IOException{
		File f = new File(configPath);
		FileWriter fw =  new FileWriter(f);
		fw.write("");		
		fw.close();
	}
	public static void main(String []args) throws Exception{
		String filePath="d:/test";
		String fileName="d:/test/test-2.txt";
		String content = "new append!";		
		StdOut.println(blockNumbersOfFile(fileName,4));
		int [] beginIndex={1,2,3};

		//����ָ����С�ļ�
		//genRandomFile(filePath+"/test-32.txt", 32);
		//	clearUpFile("d:/fileVerify/fileBlock.txt");
		//clearUpFile("d:/fileVerify/fileSector.txt");
		FileIO.readFileByLines("d:/fileVerify/fileBlock.txt");
		StdOut.println(FileIO.readSequentMulLine("d:/fileVerify/fileBlock.txt",0,50,2));
		StdOut.println(FileIO.readRandomMulLine("d:/fileVerify/fileBlock.txt",beginIndex,50,3));
	}

}
