package IHT;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import fileOperation.HDFSFileOperation;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

import tool.Sampling;
import tool.StdOut;
import tool.Stopwatch;
import IHT.IHTPADD_01.Chal;
import IHT.IndexHashTable.Item;



/**
 * IHTPADD_01进行测试
 * @author MichaelSun
 * @version 1.0
 * @date 2014.12.22
 */
public class TestIHTPADD_01 {

	public static void main (String [] args) throws Exception{
		String fileName="test-2.txt";	
		int c;					//挑战的块数量
		int s=200;				//每块的段数
		int sectorSize=20;		//160bit
		int blockSize=s*sectorSize/1000;//以k为单位
		double p=0.999;			//探测率
		int e=10;				//损坏的块数（实际中是不可预知的）

		Stopwatch start=new  Stopwatch();	//计时器
		HDFSFileOperation fileOper=new HDFSFileOperation();		
		IHTPADD_01 ihtPADP=new IHTPADD_01(false,"pairing/d/d_159.properties");
		StdOut.println("\n==============DataOwner==============\n");

		//初始设置
		StdOut.println("-------------初始化参数设置------------");
		ihtPADP.setup();


		//对文件进行预处理
		StdOut.println("\n-------------对文件预处理------------");
		Element[] pdata=fileOper.preProcessFile(fileName, blockSize,s,sectorSize, ihtPADP.getPairing().getZr());
		StdOut.println("文件预处理耗时："+start.elapsedTime()+"ms");
		Element[][] sectors=HDFSFileOperation.sectors;		
		int fileBlocks=fileOper.getBlocksOfFile(fileName, blockSize);
		c=Sampling.getSampleBlocks(fileBlocks, e,p);
		StdOut.println("采样块数："+c);

		//密钥生成
		Map<String,Element> keyMap=ihtPADP.keyGen();	        
		StdOut.println("\n-------------生成密钥------------");

		//随机生成ps、us
		Element[] ps = ihtPADP.psGen(s);
		Element[] us = ihtPADP.usGen(ps);

		//构建索引哈希表IHT
		IndexHashTable ihtable=new IndexHashTable(fileName,fileBlocks);			
		Item [] item=ihtable.createIHT(ihtPADP.getPairing().getZr(),keyMap.get(ihtPADP.SECRETKEY) , ihtPADP.getPairing().getG1());		
		//得到的哈希表
		Element[] Hid=ihtable.getHids();

		//元数据生成
		Element[] blockTags=new Element[fileBlocks];
		StdOut.println("\n-------------计算每块的标签------------");
		Stopwatch genTagTime=new  Stopwatch();	//计时器
		for(int i=0;i<fileBlocks;i++){				
			blockTags[i]=ihtPADP.metaGen(i,Hid[i+1],keyMap.get(IHTPADD_01.SECRETKEY),sectors[i],ps);
			//StdOut.println((i+1)+"块标签："+new String(Hex.encode(blockTags[i].toBytes())));
		}		
		StdOut.println("耗时："+genTagTime.elapsedTime());


		StdOut.println("\n==============verifier==============\n");

		//发起挑战		
		
		Chal [] challenge=ihtPADP.challengeGen(c,fileBlocks,fileName);
		StdOut.println("\n-------------产生挑战信息------------");
		/*for(Chal chal:challenge){
			StdOut.println("(块编号，随机数): "+"("+chal.num+","+chal.random+")");
		}
		StdOut.println("\n-------------发出挑战------------");*/


		StdOut.println("\n==============Cloud Service Provider==============\n");
		//服务器根据挑战信息，获得证据的元数据
		int [] blockNumChall=new int[c];	//块号
		Element [] vi=new Element[c];		//随机数
		Element [][] mij=new Element[c][s]; //存放挑战块的段信息
		Element [] ti=new Element[c];		//块标签	
		Item [] ids =new Item[c]; 			//挑战块的IHT中的表项
		for(int i=0;i<c;i++){
			blockNumChall[i]=challenge[i].num;
			vi[i]=challenge[i].random;
			ti[i]=blockTags[challenge[i].num-1];
			for(int j=0;j<s;j++)
				mij[i][j]=sectors[challenge[i].num-1][j];	//实现生成了pdata，服务器保存		
			ids[i]=item[challenge[i].num];	

		}


		//服务器生成证据		
		StdOut.println("-------------生成证据------------");
		Stopwatch genProofTime=new  Stopwatch();	//计时器			
		Map<String,Object>proof=ihtPADP.genProof(vi, mij, ti,us);	
		proof.put("id",ids);		//返回挑战块的ID
		//StdOut.println(proof);
		StdOut.println("耗时："+genProofTime.elapsedTime());

		
		StdOut.println("\n==============verifier==============\n");
		//检查证据
		StdOut.println("\n-------------验证数据块------------");
		Stopwatch verproofTime=new  Stopwatch();	//计时器
		boolean rTrue=ihtPADP.proofVerify(challenge,keyMap.get(ihtPADP.PUBLICKEY),proof,us);
		boolean rFalse1=ihtPADP.proofVerify(challenge,keyMap.get(ihtPADP.PUBLICKEY).twice(),proof,us);
		ids[c-1]=item[1];//错误数据测试
		proof.put("id", ids);
		boolean rFalse2=ihtPADP.proofVerify(challenge,keyMap.get(ihtPADP.PUBLICKEY),proof,us);
		StdOut.println("耗时："+verproofTime.elapsedTime());

		//验证结果
		assertTrue(rTrue);
		assertFalse(rFalse1);
		assertFalse(rFalse2);
		StdOut.println("\n-------------证据有效，数据完整------------");

		StdOut.println("总耗时："+start.elapsedTime()+"ms");
	}

}
