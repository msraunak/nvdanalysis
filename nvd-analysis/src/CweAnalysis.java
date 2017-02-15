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
	
		CweList cweList = new CweList();
		
		try {
			
			cweList.populateList();
			// cweList.printAll(); // print the list of weaknesses
			int i=0;
			ArrayList<CWE> list = cweList.getWeaknessList();
			
			for (CWE cwe: list){
				searchVulnByCweId(cwe);
			}
			
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		
	}
	
	/*
	 * Generate an URL for searching for Vulnerability by a particular year  
	 */
	public static void searchVulnByCweId(CWE cwe){
		
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
					System.out.println("CWE-"+ cwe.getId() + ": " + cwe.getName() + ": " + numOfVuln);
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
					System.out.println("CWE-"+ cwe.getId() + ": " + cwe.getName() + ": " + numOfVuln);
					cwe.setNumOfVuln(numOfVuln);
					break;
				}
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}	
			
	}
		
} // end class
