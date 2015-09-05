package MHT;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import fileOperation.HDFSFileOperation;
import it.unisa.dia.gas.jpbc.Element;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

import tool.StdOut;
import tool.Stopwatch;
import MHT.MHTPADD_01.Chal;

/**
 * 测试MHTPADD_01的功能
 * @author MichaelSun
 *
 */
public class TestMHTPADD_01 {

	public static void main (String [] args) throws Exception{
		String fileName="readFileBlock.txt";
		int blockSize=4;//以k为单位
		int c=3;	

		//计时器
		Stopwatch start=new  Stopwatch();

		HDFSFileOperation fileOper=new HDFSFileOperation();		
		MHTPADD_01 mhtPDP=new MHTPADD_01(false,"pairing/e/e.properties");	

		StdOut.println("\n==============DataOwner==============\n");

		//初始设置
		StdOut.println("-------------初始化参数设置------------");
		mhtPDP.setup();


		//对文件进行预处理
		StdOut.println("\n-------------对文件预处理------------");
		Element[] pdata=fileOper.preProcessFile(fileName,blockSize, mhtPDP.getPairing().getZr());
		Element[] gdata=mhtPDP.allGElement(pdata);
		int fileBlocks=pdata.length;	
		StdOut.println("文件预处理耗时："+start.elapsedTime()+"ms");

		StdOut.println("\n-------------生成密钥------------");
		//密钥生成
		Map<String,Element> keyMap=mhtPDP.keyGen();	        
		//产生生成标签的随机值
		Element u=mhtPDP.genRandomU();
		//元数据生成
		Element[] blockTags=new Element[fileBlocks];
		StdOut.println("\n-------------计算每块的标签------------");
		Stopwatch tagTime=new Stopwatch();
		for(int i=0;i<fileBlocks;i++){		
			blockTags[i]=mhtPDP.metaGen(i,pdata[i],gdata[i],keyMap.get(MHTPADD_01.SECRETKEY),u);
			//StdOut.println((i+1)+"块标签："+new String(Hex.encode(blockTags[i].toBytes())));
		}
		StdOut.println("标签生成耗时："+tagTime.elapsedTime()+"ms");

		//构建MHT树并对Root进行签名,签名长度512*4=2048bit
		MerkleHashTree mht=new MerkleHashTree(gdata);
		byte[] Root=mht.createMHT();				
		Element sigHashRoot=mhtPDP.sigRoot(Root, keyMap.get(MHTPADD_01.SECRETKEY));
		StdOut.println("\n-------------构建哈希树并对树根进行签名------------");
		//StdOut.println("root："+new String(Hex.encode(Root)));
		//StdOut.println("sigRoot："+new String(Hex.encode(sigRoot.toBytes())));

		
		StdOut.println("\n==============verifier==============\n");
		StdOut.println("\n-------------产生挑战信息------------");
		Stopwatch challengeTime=new Stopwatch();			
		Chal [] challenge=mhtPDP.challengeGen2(c,fileBlocks);
		StdOut.println("挑战信息耗时："+challengeTime.elapsedTime()+"ms");	
		StdOut.println("\n-------------发出挑战------------");		


		StdOut.println("\n==============Cloud Service Provider==============\n");
		
		//服务器根据挑战信息，获得证据的元数据
		int [] blockNumChall=new int[c];//块号
		Element [] vi=new Element[c];//随机数
		Element [] mi=new Element[c];
		Element [] ti=new Element[c];//块标签	
		Element [] Hmi =new Element[c];
		for(int i=0;i<c;i++){
			blockNumChall[i]=challenge[i].num;
			vi[i]=challenge[i].random;
			ti[i]=blockTags[challenge[i].num-1];
			mi[i]=pdata[challenge[i].num-1];	//实现生成了pdata，服务器保存		
			Hmi[i]=gdata[challenge[i].num-1];	//实际中Hmi应该由服务器从新计算		
		}
		
		StdOut.println("-------------生成证据------------");
		Stopwatch genProofTime =new Stopwatch();
		//服务器生成证据		
		Map<String,Object> aai=mht.genChalAAI(blockNumChall);//计算辅助索引空间 
		Map<String,Object>proof=mhtPDP.genProof(vi, mi, ti);				
		proof.put("AAI",aai);
		proof.put("Hmi",Hmi);//Hmi中的值顺序对应与挑战编号的顺序
		proof.put("sigHashRoot", sigHashRoot);
		//StdOut.println(proof);
		StdOut.println("生成证据耗时："+genProofTime.elapsedTime()+"ms");	



		StdOut.println("\n==============verifier==============\n");
		Stopwatch verProofTime=new Stopwatch();
		//校验者根据块信息计算Root
		byte[] newRoot=mht.getRootByAuxiliaryIndex(aai,blockNumChall);
		StdOut.println("-------------计算并验证Root及验证数据块------------");

		//检查证据
		boolean rTrue=mhtPDP.proofVerify(newRoot, keyMap.get(MHTPADD_01.PUBLICKEY),u,challenge,proof);
		boolean rFalse2=mhtPDP.proofVerify(Root, keyMap.get(MHTPADD_01.PUBLICKEY).twice(),u,challenge,proof);
		proof.put("sigHashRoot", sigHashRoot.twice());
		boolean rFalse1=mhtPDP.proofVerify(newRoot, keyMap.get(MHTPADD_01.PUBLICKEY),u, challenge,proof);
		StdOut.println("验证证据耗时："+verProofTime.elapsedTime()+"ms");	
	
		//验证结果
		assertTrue(rTrue);
		assertFalse(rFalse1);
		assertFalse(rFalse2);
		StdOut.println("\n-------------证据有效，数据完整------------");
		StdOut.println("校验过程总耗时："+start.elapsedTime()+" ms.");
	}
}
