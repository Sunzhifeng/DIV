package MHT;

import java.util.Random;

import org.bouncycastle.util.encoders.Hex;

public class RandomTest {
	 //连接两个字节数组
    public static byte[] arraycat(byte[] buf1,byte[] buf2)
    {
    byte[] bufret=null;
    int len1=0;
    int len2=0;
    if(buf1!=null)
    len1=buf1.length;
    if(buf2!=null)
    len2=buf2.length;
    if(len1+len2>0)
    bufret=new byte[len1+len2];
    if(len1>0)
    System.arraycopy(buf1,0,bufret,0,len1);
    if(len2>0)
    System.arraycopy(buf2,0,bufret,len1,len2);
    return bufret;
    }
    public static void main(String[] args) {
        int max=20;
        int min=10;
        Random random = new Random(20);

        int s = random.nextInt(max)%(max-min+1) + min;
        System.out.println(s);
        System.out.println("length:"+"09b6af022447baf5fc851006247064f303a6d9df21024537da628f69f5ba2dac5ce98f078874ef8e87f282bff39f098feb99ec12d293455942b7f5999928d8487cd0608312d7989d432c7d3c2a31c8c63666f2319e501c88d2770010c66c48744fd05545b90160d17fe1b6b37560ac3383449ba2e1a3b366144aaeef1fa46f38078b60a1364de2813619fa82ad019b344eb8265b2e4e3921b341e9a3bfa1459bc4bb2af75432d510428f62e02b26a94d8900d48379017f1abd5f959ddab737ccc64de19f6f9d95e3b5161e259dee0f661d4523a8dceb1e6263a2dd144b902932eac1958747a237c85e6e0e1ecfcb89e836da02b332bbb00c471f87cc6aa2cd97".length());
        byte[] testByte=new byte[10];
        for(int i=0;i<2;i++){        
        testByte[i]=2;
        System.out.println("testByte.content:"+new String(Hex.encode(testByte)));
       }
        //字节数组的“||”与字符串的“+”等效
        byte[]a="a".getBytes();
        byte[]b="b".getBytes();
        System.out.println("a"+"b");
        System.out.println(new String(arraycat(a,b)));
        
    }
}