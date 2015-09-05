package example;
import java.io.*;
import java.util.Random;
public class FileOperation {


	/**
	 * 以字节为单位读取文件，常用于读二进制文件，如图片、声音、影像等文件。
	 * @param fileName 文件的名
	 */
	public static void readFileByBytes(String fileName){
		File file = new File(fileName);
		InputStream in = null;
		try {
			//System.out.println("以字节为单位读取文件内容，一次读一个字节：");
			// 一次读一个字节
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
			System.out.println("以字节为单位读取文件内容，一次读多个字节：");
			//一次读多个字节
			byte[] tempbytes = new byte[100];
			int byteread = 0;
			in = new FileInputStream(fileName);
			//ReadFromFile.showAvailableBytes(in);
			//读入多个字节到字节数组中，byteread为一次读入的字节数
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
	 * 以字符为单位读取文件，常用于读文本，数字等类型的文件
	 * @param fileName 文件名
	 */
	public static void readFileByChars(String fileName){
		File file = new File(fileName);
		Reader reader = null;
		try {
			System.out.println("以字符为单位读取文件内容，一次读一个字节：");
			// 一次读一个字符
			reader = new InputStreamReader(new FileInputStream(file));
			int tempchar;
			while ((tempchar = reader.read()) != -1){
				//对于windows下，rn这两个字符在一起时，表示一个换行。
				//但如果这两个字符分开显示时，会换两次行。
				//因此，屏蔽掉r，或者屏蔽n。否则，将会多出很多空行。
				if (((char)tempchar) != 'r'){
					System.out.print((char)tempchar);
				}
			}
			reader.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		try {
			System.out.println("以字符为单位读取文件内容，一次读多个字节：");
			//一次读多个字符
			char[] tempchars = new char[30];
			int charread = 0;
			reader = new InputStreamReader(new FileInputStream(fileName));
			//读入多个字符到字符数组中，charread为一次读取字符数
			while ((charread = reader.read(tempchars))!=-1){
				//同样屏蔽掉r不显示
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
	 * 以行为单位读取文件，常用于读面向行的格式化文件
	 * @param fileName 文件名
	 */
	public static void readFileByLines(String fileName){
		File file = new File(fileName);
		BufferedReader reader = null;
		try {
			System.out.println("以行为单位读取文件内容，一次读一整行：");
			reader = new BufferedReader(new FileReader(file));
			String tempString = null;
			int line = 1;
			//一次读入一行，直到读入null为文件结束
			while ((tempString = reader.readLine()) != null){
				//显示行号
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
	 * 随机读取文件，一次读取一个指定长度（块数）
	 * @param fileName
	 * @param beginIndex
	 * @param blockSizeK 块的大小
	 * @param length
	 */
	public static void readFileByRandomAccess(String fileName,int beginIndex,int length){
		RandomAccessFile randomFile = null;
		try {
			randomFile = new RandomAccessFile(fileName, "r");
			long fileLength = randomFile.length();
			// 读文件的起始位置
			//int begin = (fileLength > 4) ? 4 : 0;//???????????????
			//将读文件的开始位置移到beginIndex位置。
			randomFile.seek(beginIndex);
			//到文件末尾的长度不够length
			if(length>(fileLength-beginIndex))
				length=(int)(fileLength-beginIndex);
			int byteread = 0;
			while(byteread<length){
				randomFile.readByte();
				byteread++;
			}	
			//randomFile.seek(begin);
			//System.out.print("内部读文件块的时间"+start.elapsedTime());//最多相差1毫秒
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
	 * 随机读取文件，一次读取n个指定长度（块数）
	 * ========这里我不确定beginIndex变化情况下读每次读1块，读n个长度
	 * ========与beginIndex确定后读n*length长度的区别
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
	 * 随机读取连续若干块
	 * @param filename
	 * @param bolckNumber
	 * @param blockSize
	 */
	public static void readFileByBlock(String filename,int beginBolckNumber,int blockSizeK,int nBlocklength){
		FileOperation.readFileByRandomAccess(filename,(beginBolckNumber*blockSizeK*1024),(blockSizeK*nBlocklength*1024));

	}
	/**
	 * 显示输入流中还剩的字节数
	 * @param in
	 */
	private static void showAvailableBytes(InputStream in){
		try {
			System.out.println("当前字节输入流中的字节数为:" + in.available());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	/**
	 * 生成随机大小文件（内容为数字和字符）
	 * @param fileSzie 以M为单位
	 * @throws IOException
	 */
	public static void genRandomFile( String fileName,int fileSzie) throws IOException{
		String str = "0123456789vasdjhklsadfqwiurewopt"; //自己补全字母和数字,这个字符数是作为随机取值的源
		PrintWriter pw = new PrintWriter(new FileWriter(fileName));
		int len = str.length();
		//每次写入fileSizeK,写入1024次就是 fileSizeM
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
	 * 获取文件块数
	 * @param filename
	 * @param blockSize 以K为单位
	 * @return
	 */
	public static int blockNumbersOfFile(String fileName,int blockSize){
		File file = new File(fileName);
		long number=(file.length()/(1024*blockSize));
		//System.out.println(number);
		return (int) number;
	}
	/**
	 * 根据文件路径提取文件名
	 * @param filePath
	 * @return
	 */
	public static String pathToFilename(String filePath){
		return null;
	}

}
