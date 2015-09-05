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
 * 用户本地对文件进行处理操作
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
		// 打开一个随机访问文件流，按读写方式
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
	 * 以key-value的形式保存map集合数据
	 * @param fileName 	 	配置文件路径
	 * @param map		 	 要保存的map集合
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
	 * 获取文件块数
	 * @param filePath
	 * @param blockSize 以K为单位
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

	//指定数据包含多少块
	public static int blockNumbersOfData(byte[]data,int blockSizeK) throws IOException{
		long dataLength=data.length;		
		long number=dataLength/(blockSizeK);
		long remain=dataLength%(blockSizeK);		
		return (int)(remain==0?number:number+1);
	}
	/**
	 * 
	 * @param fileSizeK	文件大小KB
	 * @param s			每块段数
	 * @param sectorSize段大小
	 * @return 			文件块数
	 */
	public static int  fileBlocks(int fileSizeK,int s,int sectorSize){
		int blockSizeK=(s*sectorSize/1000);
		int fileBlocks=(int)fileSizeK/blockSizeK;
		long remain=fileSizeK%blockSizeK;		
		fileBlocks=remain>0?fileBlocks+1:fileBlocks;
		return fileBlocks;
	}
	/**
	 * 对文件按块处理，得到对应的域中元素集合
	 * @param filePath  预处理文件路径
	 * @param blockSize 逻辑分块大小
	 * @param r 		域运算
	 * @return          所有块映射后的域元素集合
	 * @throws IOException
	 */
	public static Element[] preProcessFile(String filePath,int blockSize,Field r) throws IOException{
		int blockSizeK=blockSize*K;
		int fileBlocks=blockNumbersOfFile(filePath, blockSize);
		RandomAccessFile in = new RandomAccessFile(filePath, "r");
		byte[] blockBuff=new byte[blockSizeK];//缓冲的大小刚好与块大小相等			

		Element [] pdata=new Element[fileBlocks];			
		int remainBytes;//最后一块特殊处理
		//这里可以采取多线程并行处理，生成域元素。（mapreduce的思想）		
		for(int i=0;i<fileBlocks-1;i++){//处理前fileBlocks-1块			
			in.read(blockBuff);			
			pdata[i]=r.newElementFromHash(blockBuff,0,blockSizeK);//对数据进行域运算.这里使用hash（速度稍慢），也可以用newElementFromBytes
			//pdata[i]=r.newElementFromBytes(blockBuff);//对数据进行域运算.这里使用hash（速度稍慢），也可以用newElementFromBytes
		}
		remainBytes=in.read(blockBuff);
		in.close();
		if(remainBytes==blockSizeK){
			pdata[fileBlocks-1]=r.newElementFromHash(blockBuff,0,blockSizeK);
		}else{//最后一块可能不够，需特殊处理,采用0填充
			for(int k=remainBytes;k<blockBuff.length;k++){
				blockBuff[k]=0;			
			}
			pdata[fileBlocks-1]=r.newElementFromHash(blockBuff,0,blockSizeK);			
			System.out.print("最后块大小："+remainBytes);
		}		
		return pdata;
	}
	/**
	 * 对文件进行分块与分段预处理
	 * @param filePath		文件名
	 * @param blockSize		块大小
	 * @param s				每块的段数
	 * @param sectorSize	段大小
	 * @param r				大素数阶
	 * @return				n个文件块及分段信息集合
	 * @throws IOException
	 */
	//对于不大于32M的文件可以按此方法处理
	public static Map<String,Object> preProcessFile(String filePath,int blockSize,int s,int sectorSize,Field r) throws IOException{
		int blockSizeK=blockSize*K;
		int fileBlocks=blockNumbersOfFile(filePath, blockSize);
		RandomAccessFile in = new RandomAccessFile(filePath, "r");

		byte[] blockBuff;//缓冲的大小刚好与块大小相等		
		Element [] pdata=new Element[fileBlocks];//块元素信息			
		List<Element[]> nSectors=new ArrayList<Element[]>(fileBlocks);//段元素信息	

		//这里可以采取多线程并行处理，生成域元素。（mapreduce的思想）		
		for(int i=0;i<fileBlocks-1;i++){//处理前fileBlocks-1块
			blockBuff=new byte[blockSizeK];
			in.read(blockBuff,0,blockBuff.length);			
			pdata[i]=r.newElementFromBytes(blockBuff);//对数据进行域运算.这里使用hash（速度稍慢），也可以用newElementFromBytes
			nSectors.add(preProcessBlock(s, blockBuff, sectorSize, r));//第i块的分段信息加到sectors中
		}
		blockBuff=new byte[blockSizeK];
		int remainBytes=in.read(blockBuff);	
		if(remainBytes==blockSizeK){//最后一块特殊处理
			pdata[fileBlocks-1]=r.newElementFromBytes(blockBuff);
			nSectors.add(preProcessBlock(s, blockBuff, sectorSize, r));
		}else{//最后一块可能不够，需特殊处理,采用0填充
			for(int k=remainBytes;k<blockBuff.length;k++){
				blockBuff[k]=0;			
			}
			pdata[fileBlocks-1]=r.newElementFromBytes(blockBuff);	
			nSectors.add(preProcessBlock(s, blockBuff, sectorSize, r));
		}
	
			in.close();
		//保存块及段信息到文件
	   //saveElementArray(FILEBLOCK, pdata);
	//	saveListElementArray(FILESECTOR, nSectors);
		
		Map<String,Object> blockSector=new HashMap<String,Object>(2);
		blockSector.put("pdata", pdata);
		blockSector.put("nSectors", nSectors);
		return blockSector;
	}
	
	//获得指定块及段内容
	public static Map<String,Object> preProcessFile(String filePath,int []blockNums,int blockSize,int s,int sectorSize,Field r) throws IOException{
		int blockSizeK=blockSize*K;
		//int fileBlocks=blockNumbersOfFile(filePath, blockSize);
		
		RandomAccessFile in = new RandomAccessFile(filePath, "r");

		byte[] blockBuff;//缓冲的大小刚好与块大小相等		
		Element [] cpdata=new Element[blockNums.length];//块元素信息			
		List<Element[]> cSectors=new ArrayList<Element[]>(blockNums.length);//段元素信息	

		//这里可以采取多线程并行处理，生成域元素。（mapreduce的思想）		
		for(int i=0;i<blockNums.length;i++){//处理前fileBlocks-1块
			blockBuff=new byte[blockSizeK];
			in.seek((blockNums[i]-1)*blockSizeK);
			in.read(blockBuff,0,blockBuff.length);			
			cpdata[i]=r.newElementFromBytes(blockBuff);//对数据进行域运算.这里使用hash（速度稍慢），也可以用newElementFromBytes
			cSectors.add(preProcessBlock(s, blockBuff, sectorSize, r));//第i块的分段信息加到sectors中
		}
		
		in.close();	
		
		Map<String,Object> blockSector=new HashMap<String,Object>(2);
		blockSector.put("cpdata", cpdata);
		blockSector.put("cSectors", cSectors);
		StdOut.println(cSectors);
		return blockSector;
	}
	//获得c个文件块标签
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
	
	//获得c个索引哈希表项
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
	//大文件处理大于32M，二级缓存
	public static void preProcessLargeFile(String filePath,int blockSize,int s,int sectorSize,Field r) throws FileNotFoundException, IOException {  	       
		int blockSizeK=blockSize*K;
		File file = new File(filePath);
		long fileLength=file.length();//文件的总长度
		int length=0x4000000;//64M，每次读入内存的数据量
		int count=(int)(fileLength/length);//读多少次
		int remain=(int)fileLength%length;		
		count=(remain==0?count:count+1);

		FileChannel fc=new RandomAccessFile(file, "r").getChannel();
		int blockRemain=0;//64M数据除以文件块大小余下的字节数
		for(int i=0;i<count;i++){			
			int start=i*length-blockRemain;//每次映射的起始位置
			//StdOut.println(start);
			MappedByteBuffer inputBuffer;
			//内存映射文件输入流
			if (fileLength - start >= length){
				inputBuffer = fc.map(FileChannel.MapMode.READ_ONLY, start,length);// 读取64M
			}else{
				inputBuffer = fc.map(FileChannel.MapMode.READ_ONLY, start,fileLength-start);// 读取大文件  
			}

			int buffSize=16*blockSizeK;	//！！！！这里的16个块不可能大于64M	
			byte[] blocksBuff = new byte[buffSize];// 每次处理16个块大小数据  	
			for (int offset = 0; offset < length; offset += buffSize) {  
				if (length - offset >= buffSize) { 				
					inputBuffer.get(blocksBuff); 
					// 将得到的16块内容进行计算；  
					preProcessData(blocksBuff, blockSizeK, s, sectorSize, r);
				} else {  //最后一块不足buffsize大小，特殊处理		
					blockRemain=length-offset;//剩余部分重新读取下次处理

				}  
			}
		}
		fc.close();

	}

	//对一批数据进行分块与分段处理,没有采用填充，data不一定是块大小的正数倍
	private static Map<String,Object> preProcessData(byte[] data,int blockSizeK,int s,int sectorSize,Field r) throws IOException{
		int dataBlocks=blockNumbersOfData(data, blockSizeK);		
		int remain=data.length-(dataBlocks-1)*blockSizeK;//最后一块的字节数

		Element [] pdata=new Element[dataBlocks];//块元素信息			
		List<Element[]> nSectors=new ArrayList<Element[]>(dataBlocks);//段元素信息	
		byte[] blockBuff;

		//这里可以采取多线程并行处理，生成域元素。（mapreduce的思想）		
		for(int i=0;i<dataBlocks-1;i++){//处理前fileBlocks-1块
			blockBuff=subByteArray(data, i*blockSizeK, blockSizeK);
			pdata[i]=r.newElementFromHash(blockBuff,0,blockSizeK);//对数据进行域运算.这里使用hash（速度稍慢），也可以用newElementFromBytes
			nSectors.add(preProcessBlock(s, blockBuff, sectorSize, r));//第i块的分段信息加到sectors中
		}
		blockBuff=new byte[blockSizeK];

		if(remain==blockSizeK)//处理最后一块			
			subByteArray(data, (dataBlocks-1)*blockSizeK, blockSizeK,blockBuff);
		else
			subByteArray(data, (dataBlocks-1)*blockSizeK, remain,blockBuff);

		pdata[dataBlocks-1]=r.newElementFromHash(blockBuff,0,blockSizeK);
		nSectors.add(preProcessBlock(s, blockBuff, sectorSize, r));
		//保存信息到文件
		FileIO.appendElementArray(FILEBLOCK, pdata);	
		FileIO.appendListElementArray(FILESECTOR, nSectors);
		Map<String,Object> blockSector=new HashMap<String,Object>(2);
		blockSector.put("pdata", pdata);
		blockSector.put("nSectors", nSectors);
		return blockSector;
	}
	
	/**
	 * 对块进行分段处理
	 * @param s 			段数
	 * @param blockData 	块数据
	 * @param sectorSize 	段大小
	 * @param r 			素数域
	 * @return 				s个域元素	
	 */
	public static Element[] preProcessBlock(int s,byte[] blockData,int sectorSize,Field r){
		Element[] sectorNums=new Element[s];		
		for(int i=0;i<s;i++){
			byte[] buff=subByteArray(blockData,i*sectorSize,sectorSize);
			//对于分段采用hash的方式
			sectorNums[i]=(r.newElementFromBytes(buff));			
		}
		return sectorNums;
	}
	/**
	 * 复制数组中指定范围内的元素
	 * @param a			给定数组
	 * @param offset	要复制元素的起始编号
	 * @param len		要复制元素的终止编号
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
			System.out.println("截取范围越界！！");
			return;
		}
		for(int i=0;i<len;i++){
			to[i]=from[offset+i];
		}
	}
	//默认填充0,字节数组元素的默认值为0
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

		//生成指定大小文件
		//genRandomFile(filePath+"/test-32.txt", 32);
		//	clearUpFile("d:/fileVerify/fileBlock.txt");
		//clearUpFile("d:/fileVerify/fileSector.txt");
		FileIO.readFileByLines("d:/fileVerify/fileBlock.txt");
		StdOut.println(FileIO.readSequentMulLine("d:/fileVerify/fileBlock.txt",0,50,2));
		StdOut.println(FileIO.readRandomMulLine("d:/fileVerify/fileBlock.txt",beginIndex,50,3));
	}

}
