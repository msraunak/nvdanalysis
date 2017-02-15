import java.io.IOException;

/*
 * The main class to drive the program
 * @author msr4
 */

public class CweAnalysis {

	public static void main (String[] args){
	
		CweList cweList = new CweList();
		
		try {
			
			cweList.populateList();
			cweList.printAll(); // print the list of weaknesses
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		
	}
	
}
