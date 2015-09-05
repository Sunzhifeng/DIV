/**
 * 功能描述：
 * 1.采用非对称的双线性映射
 * 2.采用带签名保护的索引哈希表
 * 3.服务器对数据标签进行累成，由服务器计算，最小化校验者的计算量
 * 4.服务器端对数据标签累成的改进版本
 * 5.批量校验
 * 6.包含对信息盲化处理
 */

package FEPAD;
import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;


import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

import FEPAD.Verifier.Chal;
import JDBC.DBOperation;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import tool.GenerateRandom;
import tool.PropertiesUtil;
import tool.SortAlg;

/**
 * 
 * @author MichaelSun
 * @version 2.0
 * @date  2015.6.5
 * 
 */
public class PADD {
	public static final String FILECONFIG="fileconfig.properties";
	public static final String PUBLIC="public";
	public static final String FILETAG="filetag";
	
	public static void main(String[] args) throws IOException {
		
		int n=512;//总块数
		int c=100;//挑战块数
		
		//校验者
		System.out.print("Verifier computes challenge......\t\t");		
		Verifier verifier=new Verifier();		
		List<Chal> challenges=verifier.challengeGen(c, n);		
		System.out.println("[ok].");
		
		
		//云服务商
		System.out.print("CSP computes integerity proof......\t\t");
		CloudServiceProvider csp=new CloudServiceProvider();
		Map<String,Element> proof=csp.genProof(challenges);
		System.out.println("[ok].");


		//校验者
		System.out.print("Verifier verifies proof......\t\t");		
		boolean isTrue=verifier.proofVerify(challenges, proof);
		assertTrue(isTrue);		
		Element t=proof.get("aggreTMul").twice();
		proof.put("aggreTMul", t);
		boolean isFalse=verifier.proofVerify(challenges, proof);
		assertFalse(isFalse);
		System.out.println("[ok].");

	}



}
