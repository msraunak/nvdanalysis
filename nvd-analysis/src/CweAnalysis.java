import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 * The main class to drive the program
 * @author msr4
 */

public class CweAnalysis {

	public static void main (String[] args){
	
		CweList objCweList = new CweList();
		int begYear, endYear;
		begYear=1998;
		endYear=2016;
		try {
			// Read in from cwelist.txt file different categories of CWEs 
			objCweList.populateList();

			//ArrayList<CWE> allCWEs = objCweList.getWeaknessListAll();
			// for (CWE objCwe: allCWEs){
				// searchByCweId(objCwe);
			//}

			ArrayList<CWE> nistCWEs = objCweList.getNISTList();
			
			for (CWE objCwe: nistCWEs ) {
				for (int year=begYear; year<=endYear; year++){
						// find the number of vulnerabilities and update the CWE object accordingly 
						searchByCweIdAndYear(objCwe, year) ;
				}
			}
			// print all the NIST cwe info
			objCweList.sortTheLists();
			objCweList.printAllNISTCWEs();
			objCweList.printAllNistCWEsToFile("NumOfVulnNist19ByYear.txt");
			
			// objCweList.printAllCWEs();
			
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		
	}
	
	
	
	/*
	 * Generate an URL for searching for Vulnerability by a particular year  
	 */
	public static void searchByCweId(CWE cwe){
		
		String urlString = "https://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cves=on&cwe_id=CWE-" + cwe.getId(); 
		
		try {
			URL url = new URL(urlString);
			
			BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));
			
			String strLine = "";
			String patternRegEx = "(.*)There are <strong>(.*)</strong> matching records(.*)";
			Pattern pattern = Pattern.compile(patternRegEx);
		    Matcher matcher;
		    
			while (null != (strLine = br.readLine())) {
				
				matcher = pattern.matcher(strLine);	
				if (matcher.matches()){
					int numOfVuln = Integer.parseInt(matcher.group(2).replaceAll(",","")); //strip all commas in the matched gropu
					System.out.println("CWE-"+ cwe.getId() + ": " + cwe.getName() + ": " 
											+ cwe.getType() + " : " + numOfVuln);
					cwe.setNumOfVuln(numOfVuln);
					break;
				}
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}	
	}
	
	/**
	 * Search By year
	 * @param cwe
	 * @param year
	 */
	public static void searchByCweIdAndYear(CWE cwe, int year) {
			
	String urlString = "";
		
		urlString += "https://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cves=on&cwe_id=CWE-" + cwe.getId(); 
		urlString += "&pub_date_start_month=0&pub_date_start_year=" + year;
		urlString += "&pub_date_end_month=11&pub_date_end_year=" + year;
		
		try {

			URL url = new URL(urlString);

			BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));
			
			String strLine = "";
			String patternRegEx = "(.*)There are <strong>(.*)</strong> matching records(.*)";
			Pattern pattern = Pattern.compile(patternRegEx);
		    Matcher matcher;
		    
			while (null != (strLine = br.readLine())) {
				
				matcher = pattern.matcher(strLine);	
				if (matcher.matches()){
					int numOfVuln = Integer.parseInt(matcher.group(2).replaceAll(",","")); //strip all commas in the matched gropu
					System.out.println("CWE-"+ cwe.getId() + ": " + cwe.getName() 
										+ ": " + cwe.getType() + ": " + year + ":" + numOfVuln);
					
					//cwe.setNumOfVuln(numOfVuln);
					cwe.addNumVulnInYear(year, numOfVuln);
					break;
				}
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}	
			
	}
		
} // end class
