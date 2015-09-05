package example;
import java.io.*;
import java.util.Random;
public class FileOperation {


	/**
	 * ���ֽ�Ϊ��λ��ȡ�ļ��������ڶ��������ļ�����ͼƬ��������Ӱ����ļ���
	 * @param fileName �ļ�����
	 */
	public static void readFileByBytes(String fileName){
		File file = new File(fileName);
		InputStream in = null;
		try {
			//System.out.println("���ֽ�Ϊ��λ��ȡ�ļ����ݣ�һ�ζ�һ���ֽڣ�");
			// һ�ζ�һ���ֽ�
			in = new FileInputStream(file);
			int tempbyte;
			while((tempbyte=in.read()) != -1){
				//System.out.write(tempbyte);
			}
			in.close();
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
		/**try {
			System.out.println("���ֽ�Ϊ��λ��ȡ�ļ����ݣ�һ�ζ�����ֽڣ�");
			//һ�ζ�����ֽ�
			byte[] tempbytes = new byte[100];
			int byteread = 0;
			in = new FileInputStream(fileName);
			//ReadFromFile.showAvailableBytes(in);
			//�������ֽڵ��ֽ������У�bytereadΪһ�ζ�����ֽ���
			while ((byteread = in.read(tempbytes)) != -1){
				//System.out.write(tempbytes, 0, byteread);
			}
		} catch (Exception e1) {
			e1.printStackTrace();
		} finally {
			if (in != null){
				try {
					in.close();
				} catch (IOException e1) {
				}
			}
		}
		 */
	}
	/**
	 * ���ַ�Ϊ��λ��ȡ�ļ��������ڶ��ı������ֵ����͵��ļ�
	 * @param fileName �ļ���
	 */
	public static void readFileByChars(String fileName){
		File file = new File(fileName);
		Reader reader = null;
		try {
			System.out.println("���ַ�Ϊ��λ��ȡ�ļ����ݣ�һ�ζ�һ���ֽڣ�");
			// һ�ζ�һ���ַ�
			reader = new InputStreamReader(new FileInputStream(file));
			int tempchar;
			while ((tempchar = reader.read()) != -1){
				//����windows�£�rn�������ַ���һ��ʱ����ʾһ�����С�
				//������������ַ��ֿ���ʾʱ���ỻ�����С�
				//��ˣ����ε�r����������n�����򣬽������ܶ���С�
				if (((char)tempchar) != 'r'){
					System.out.print((char)tempchar);
				}
			}
			reader.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		try {
			System.out.println("���ַ�Ϊ��λ��ȡ�ļ����ݣ�һ�ζ�����ֽڣ�");
			//һ�ζ�����ַ�
			char[] tempchars = new char[30];
			int charread = 0;
			reader = new InputStreamReader(new FileInputStream(fileName));
			//�������ַ����ַ������У�charreadΪһ�ζ�ȡ�ַ���
			while ((charread = reader.read(tempchars))!=-1){
				//ͬ�����ε�r����ʾ
				if ((charread == tempchars.length)&&(tempchars[tempchars.length-1] != 'r')){
					System.out.print(tempchars);
				}else{
					for (int i=0; i<charread; i++){
						if(tempchars[i] == 'r'){
							continue;
						}else{
							System.out.print(tempchars[i]);
						}
					}
				}
			}

		} catch (Exception e1) {
			e1.printStackTrace();
		}finally {
			if (reader != null){
				try {
					reader.close();
				} catch (IOException e1) {
				}
			}
		}
	}
	/**
	 * ����Ϊ��λ��ȡ�ļ��������ڶ������еĸ�ʽ���ļ�
	 * @param fileName �ļ���
	 */
	public static void readFileByLines(String fileName){
		File file = new File(fileName);
		BufferedReader reader = null;
		try {
			System.out.println("����Ϊ��λ��ȡ�ļ����ݣ�һ�ζ�һ���У�");
			reader = new BufferedReader(new FileReader(file));
			String tempString = null;
			int line = 1;
			//һ�ζ���һ�У�ֱ������nullΪ�ļ�����
			while ((tempString = reader.readLine()) != null){
				//��ʾ�к�
				System.out.println("line " + line + ": " + tempString);
				line++;
			}
			reader.close();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (reader != null){
				try {
					reader.close();
				} catch (IOException e1) {
				}
			}
		}
	}
	/**
	 * �����ȡ�ļ���һ�ζ�ȡһ��ָ�����ȣ�������
	 * @param fileName
	 * @param beginIndex
	 * @param blockSizeK ��Ĵ�С
	 * @param length
	 */
	public static void readFileByRandomAccess(String fileName,int beginIndex,int length){
		RandomAccessFile randomFile = null;
		try {
			randomFile = new RandomAccessFile(fileName, "r");
			long fileLength = randomFile.length();
			// ���ļ�����ʼλ��
			//int begin = (fileLength > 4) ? 4 : 0;//???????????????
			//�����ļ��Ŀ�ʼλ���Ƶ�beginIndexλ�á�
			randomFile.seek(beginIndex);
			//���ļ�ĩβ�ĳ��Ȳ���length
			if(length>(fileLength-beginIndex))
				length=(int)(fileLength-beginIndex);
			int byteread = 0;
			while(byteread<length){
				randomFile.readByte();
				byteread++;
			}	
			//randomFile.seek(begin);
			//System.out.print("�ڲ����ļ����ʱ��"+start.elapsedTime());//������1����
			//			while ((byteread = randomFile.read()) != -1){
			//				//System.out.write(bytes, 0, byteread);
			//			}
		} catch (IOException e){
			e.printStackTrace();
		} finally {
			if (randomFile != null){
				try {
					
					randomFile.close();
				} catch (IOException e1) {
				}
			}
		}
	}
	/**
	 * �����ȡ�ļ���һ�ζ�ȡn��ָ�����ȣ�������
	 * ========�����Ҳ�ȷ��beginIndex�仯����¶�ÿ�ζ�1�飬��n������
	 * ========��beginIndexȷ�����n*length���ȵ�����
	 * @param fileName
	 * @param beginIndex
	 * @param length
	 * @param n
	 */
	public static void readFileByRandomAccess(String fileName,int beginIndex,int length,int n){
		RandomAccessFile randomFile = null;
		try {			
			randomFile = new RandomAccessFile(fileName, "r");
			long fileLength = randomFile.length();	
			int randomPosit;
			for (int i = 0; i < n; i++) {
				randomPosit=new Random().nextInt((int)(fileLength-length));			
				randomFile.seek(randomPosit);	
				int byteread = 0;
				while(byteread<length){
					randomFile.readByte();
					byteread++;
				}	
			}

		} catch (IOException e){
			e.printStackTrace();
		} finally {
			if (randomFile != null){
				try {
					randomFile.close();
				} catch (IOException e1) {
				}
			}
		}
	}

	/**
	 * �����ȡ�������ɿ�
	 * @param filename
	 * @param bolckNumber
	 * @param blockSize
	 */
	public static void readFileByBlock(String filename,int beginBolckNumber,int blockSizeK,int nBlocklength){
		FileOperation.readFileByRandomAccess(filename,(beginBolckNumber*blockSizeK*1024),(blockSizeK*nBlocklength*1024));

	}
	/**
	 * ��ʾ�������л�ʣ���ֽ���
	 * @param in
	 */
	private static void showAvailableBytes(InputStream in){
		try {
			System.out.println("��ǰ�ֽ��������е��ֽ���Ϊ:" + in.available());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	/**
	 * ���������С�ļ�������Ϊ���ֺ��ַ���
	 * @param fileSzie ��MΪ��λ
	 * @throws IOException
	 */
	public static void genRandomFile( String fileName,int fileSzie) throws IOException{
		String str = "0123456789vasdjhklsadfqwiurewopt"; //�Լ���ȫ��ĸ������,����ַ�������Ϊ���ȡֵ��Դ
		PrintWriter pw = new PrintWriter(new FileWriter(fileName));
		int len = str.length();
		//ÿ��д��fileSizeK,д��1024�ξ��� fileSizeM
		for (int i = 0; i < 1024; i++)
		{
			StringBuilder s = new StringBuilder();
			for (int j = 0; j < (fileSzie*1024); j++)
			{
				s.append(str.charAt((int)(Math.random()*len)));
			}
			pw.println(s.toString());
		}
		pw.close();
	}
	/**
	 * ��ȡ�ļ�����
	 * @param filename
	 * @param blockSize ��KΪ��λ
	 * @return
	 */
	public static int blockNumbersOfFile(String fileName,int blockSize){
		File file = new File(fileName);
		long number=(file.length()/(1024*blockSize));
		//System.out.println(number);
		return (int) number;
	}
	/**
	 * �����ļ�·����ȡ�ļ���
	 * @param filePath
	 * @return
	 */
	public static String pathToFilename(String filePath){
		return null;
	}

}
