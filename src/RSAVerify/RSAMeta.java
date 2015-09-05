package RSAVerify;

import java.math.BigInteger;

public class RSAMeta {   
	public  BigInteger G;
	public  BigInteger GS;
	public  BigInteger S;
	public  int  R;
	public  BigInteger N; // n=q*p 
	public  BigInteger FN;//FN=¦Õ(n)=(q-1)(p-1)
	

	public Object getG() {
		return G;
	}


	public void setG(BigInteger g) {
		G = g;
	}


	public Object getGS() {
		return GS;
	}


	public void setGS(BigInteger gS) {
		GS = gS;
	}


	public Object getS() {
		return S;
	}


	public void setS(BigInteger s) {
		S = s;
	}


	public Object getR() {
		return R;
	}


	public void setR(int r) {
		R = r;
	}


	public Object getN() {
		return N;
	}


	public void setN(BigInteger n) {
		N = n;
	}

}
