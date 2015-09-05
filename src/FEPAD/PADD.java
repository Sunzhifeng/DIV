/**
 * ����������
 * 1.���÷ǶԳƵ�˫����ӳ��
 * 2.���ô�ǩ��������������ϣ��
 * 3.�����������ݱ�ǩ�����۳ɣ��ɷ��������㣬��С��У���ߵļ�����
 * 4.�������˶����ݱ�ǩ�۳ɵĸĽ��汾
 * 5.����У��
 * 6.��������Ϣä������
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
		
		int n=512;//�ܿ���
		int c=100;//��ս����
		
		//У����
		System.out.print("Verifier computes challenge......\t\t");		
		Verifier verifier=new Verifier();		
		List<Chal> challenges=verifier.challengeGen(c, n);		
		System.out.println("[ok].");
		
		
		//�Ʒ�����
		System.out.print("CSP computes integerity proof......\t\t");
		CloudServiceProvider csp=new CloudServiceProvider();
		Map<String,Element> proof=csp.genProof(challenges);
		System.out.println("[ok].");


		//У����
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
