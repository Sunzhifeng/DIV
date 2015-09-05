package MHT;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import fileOperation.HDFSFileOperation;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

import tool.Sampling;
import tool.StdOut;
import tool.Stopwatch;
import MHT.MHTPADD_02.Chal;
import MHT.MerkleHashTree.Node;

/**
 * MHTPADD_02进行测试
 * @author MichaelSun
 * @version 2.0
 * @date 2014.11.21
 */
public class TestMHTPADD_02 {

	public static void main (String [] args) throws Exception{
		String fileName="test-2.txt";	
		int c=30;					//挑战的块数量
		int s=100;				//每块的段数
		int sectorSize=20;		//160bit
		int blockSize=s*sectorSize/1000;//以k为单位
		double p=0.999;			//探测率
		int e=10;				//损坏的块数（实际中是不可预知的）	
		Stopwatch start=new  Stopwatch();	//计时器
		HDFSFileOperation fileOper=new HDFSFileOperation();		
		MHTPADD_02 mhtPDP=new MHTPADD_02(false,"pairing/e/e.properties");	
		//MHTPADD mhtPDP=new MHTPADD(false,"pairing/d/d_159.properties");	

		StdOut.println("\n==============DataOwner==============\n");

		//初始设置
		StdOut.println("-------------初始化参数设置------------");
		mhtPDP.setup();


		//对文件进行预处理
		StdOut.println("\n-------------对文件预处理------------");
		Element[] pdata=fileOper.preProcessFile(fileName, blockSize,s,sectorSize, mhtPDP.getPairing().getZr());
		Element[][] sectors=HDFSFileOperation.sectors;
		Element[] gdata=mhtPDP.allGElement(pdata);
		int fileBlocks=fileOper.getBlocksOfFile(fileName, blockSize);
		c=Sampling.getSampleBlocks(fileBlocks, e,p);
		StdOut.println("采样块数："+c);
		StdOut.println("文件预处理耗时："+start.elapsedTime()+"ms");

		//密钥生成
		Map<String,Element> keyMap=mhtPDP.keyGen();	        
		
		//计算随机值
		Element[] us=mhtPDP.pusGen(s);		

		//元数据生成
		Element[] blockTags=new Element[fileBlocks];
		StdOut.println("\n-------------计算每块的标签------------");
		for(int i=0;i<fileBlocks;i++){				
			blockTags[i]=mhtPDP.metaGen(i,gdata[i],keyMap.get(MHTPADD_01.SECRETKEY),sectors[i],us);
			StdOut.println((i+1)+"块标签："+new String(Hex.encode(blockTags[i].toBytes())));
		}		

		//构建MHT树并对Root进行签名,签名长度512*4=2048bit
		MerkleHashTree mht=new MerkleHashTree(gdata);
		byte[] Root=mht.createMHT();				
		Element sigHashRoot=mhtPDP.sigRoot(Root, keyMap.get(MHTPADD_01.SECRETKEY));
		StdOut.println("\n-------------构建哈希树并对树根进行签名------------");
		StdOut.println("root："+new String(Hex.encode(Root)));
		StdOut.println("sigRoot："+new String(Hex.encode(sigHashRoot.toBytes())));

		StdOut.println("\n==============verifier==============\n");

		StdOut.println("\n-------------产生挑战信息------------");
		//发起挑战		
		Chal [] challenge=mhtPDP.challengeGen(c,fileBlocks);	
		
		StdOut.println("\n-------------发出挑战------------");

		StdOut.println("\n==============Cloud Service Provider==============\n");
		//服务器根据挑战信息，获得证据的元数据
		int [] blockNumChall=new int[c];//块号
		Element [] vi=new Element[c];//随机数
		Element [][] mij=new Element[c][s];//存放挑战块的段信息
		Element [] ti=new Element[c];//块标签	
		Element [] Hmi =new Element[c];
		for(int i=0;i<c;i++){
			blockNumChall[i]=challenge[i].num;
			vi[i]=challenge[i].random;
			ti[i]=blockTags[challenge[i].num-1];
			for(int j=0;j<s;j++)
				mij[i][j]=sectors[challenge[i].num-1][j];	//实现生成了pdata，服务器保存		
			Hmi[i]=gdata[challenge[i].num-1];			
		}
		StdOut.println("-------------生成证据------------");

		//服务器生成证据		
		Map<String,Object>aai=mht.genChalAAI(blockNumChall);//计算辅助索引空间 
		Map<String,Object>proof=mhtPDP.genProof(vi, mij, ti,s);			
		proof.put("AAI",aai);
		proof.put("Hmi",Hmi);//Hmi中的值顺序对应与挑战编号的顺序
		proof.put("sigHashRoot",sigHashRoot);	
		StdOut.println(proof);



		StdOut.println("\n==============verifier==============\n");

		//校验者根据块信息计算Root
		byte[] newRoot=mht.getRootByAuxiliaryIndex(aai,blockNumChall);
		StdOut.println("-------------计算并验证Root------------");
		StdOut.println("newRoot："+new String(Hex.encode(newRoot)));

		//检查证据
		StdOut.println("\n-------------验证数据块------------");
		boolean rTrue=mhtPDP.proofVerify(newRoot, keyMap.get(MHTPADD_02.PUBLICKEY),us,challenge, proof);
		boolean rFalse2=mhtPDP.proofVerify(Root, keyMap.get(MHTPADD_02.PUBLICKEY).twice(), us,challenge,proof);
		proof.put("sigHashRoot", sigHashRoot.twice());
		boolean rFalse1=mhtPDP.proofVerify(newRoot, keyMap.get(MHTPADD_02.PUBLICKEY), us,challenge,proof);


		//验证结果
		assertTrue(rTrue);
		assertFalse(rFalse1);
		assertFalse(rFalse2);
		StdOut.println("\n-------------证据有效，数据完整------------");

		StdOut.println("总耗时："+start.elapsedTime()+"ms");
	}

}
