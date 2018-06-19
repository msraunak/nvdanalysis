import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 * The main class to drive the program
 * @author msr4
 */

public class CweAnalysis {
	
	/**The main method to call the necessary methods to collect CWE data
	 */
	public static void main (String[] args){
	
		
		int begYear, endYear; //declaration of search year parameters
		String fileName = "IISVuln1998-2018Nist19.txt"; //File name to store the number of vulnerabilities per CWE category
		begYear=1998;
		endYear=2018;
		String product = "iis";
		String vendor = "microsoft";
	
		gatherVulnPerVendorAndProductNist19(begYear, endYear, fileName, vendor, product);
		//printTotalVulnReportedInYear(begYear, endYear); 
		//gatherVulnPerVendorAndProduct(begYear, endYear, fileName, vendor, product);
		//gatherVulnForAllCwes(begYear, endYear, fileName); //call to method to collect the CWE data 
		//vulnByNIST19CweAndYear(begYear, endYear);
		
		
	} // end main

	/** Print all vulnerabilities reported year by year 
	 * @param begYear beginning year of the search
	 * @param endYear end year of the search
	 */
	public static void printTotalVulnReportedInYear(int begYear, int endYear){
	
		Map <Integer,Integer> totalVulnPerYear = new TreeMap<Integer, Integer>(); //map that stores the year and the total vulnerabilities per year  
		
		//putting the vulnerabilities per year into the map
		for (int year=begYear; year<=endYear; year++){
			totalVulnPerYear.put(year, vulnReportedInAYear(year) );
		}
		
		String strYears="";
		String strVulns="";
		for (Integer yr: totalVulnPerYear.keySet() ) { //loops through all the years in the map
			strYears =  strYears+ yr +"\t";//adds all the years to a string
			strVulns = strVulns+ totalVulnPerYear.get(yr) + "\t";//adds the number of vulnerabilities to a string 
		}
		
		//prints the info collected in the previous loop	
		System.out.println(strYears); 
		System.out.println(strVulns);
		
	}
	
	/** Collect the vulnCount for every CWE by Year and print it 
	 * @param begYear the beginning year of the search 
	 * @param endYear the end year of the search
	 * @param fileName the file name for data to be stored
	 */
	public static void gatherVulnForAllCwes(int begYear, int endYear, String fileName){
		
		CweList objCweList = new CweList(); //creates a CWE object list
		
		ArrayList<CWE> allCWEs = objCweList.getWeaknessListAll(); // creates an array list of all the CWE objects
		for (CWE objCwe: allCWEs ) { //loops through all the CWE entries in the CWE list 
			for (int year=begYear; year<=endYear; year++){
					// find the number of reported vulnerabilities and update the CWE object accordingly 
					searchByCweIdAndYear(objCwe, year);
			}
		}
		
		objCweList.sortTheLists(); //sorts the CWE list
		objCweList.printAllCWEsToFile(fileName); //prints all the CWE to the txt file after sorting 
						
	}
	
	
	/** This will gather the number of vulnerabilities for a specific product associated with a specific vendor
	 * @param begYear beginning year of the search
	 * @param endYear end year of the search
	 * @param fileName file to which the data will be written
	 * @param Vendor the CPE vendor of the product
	 * @param product the specific piece of software
	 */
	public static void gatherVulnPerVendorAndProduct(int begYear, int endYear, String fileName, String Vendor, String product)
	{
		CweList objCweList = new CweList();
		
		ArrayList<CWE> productCWEs = objCweList.getWeaknessListAll(); //creates an array list of all the CWE objects
		for (CWE obj: productCWEs)
		{
			for(int year = begYear; year<=endYear; year++)
			{
				searchByProductAndYear(obj, Vendor, product, year);
			}
		}
		objCweList.sortTheLists();
		objCweList.printAllCWEsToFile(fileName);
	}
	
	/** This will gather the number of vulnerabilities for a specific product associated with a specific vendor
	 * @param begYear beginning year of the search
	 * @param endYear end year of the search
	 * @param fileName file to which the data will be written
	 * @param Vendor the CPE vendor of the product
	 * @param product the specific piece of software
	 */
	public static void gatherVulnPerVendorAndProductNist19(int begYear, int endYear, String fileName, String Vendor, String product)
	{
		CweList objCweList = new CweList();
		
		ArrayList<CWE> productCWEs = objCweList.getNISTList(); //creates an array list of all the CWE objects
		for (CWE obj: productCWEs)
		{
			for(int year = begYear; year<=endYear; year++)
			{
				searchByProductAndYear(obj, Vendor, product, year);
			}
		}
		objCweList.sortTheLists();
		objCweList.printAllNistCWEsToFile(fileName);
	}
	
	/** Record the NIST19 vulnerabilities as reported in every year. 
	 * More focused collection of CWEs than gatherVulnForAllCwes  
	 * @param begYear the beginning year of the search
	 * @param endYear the end year of the search
	 */
	public static void vulnByNIST19CweAndYear(int begYear, int endYear){
		
		CweList objCweList = new CweList(); //creates the CWE object list
		ArrayList<CWE> nistCWEs = objCweList.getNISTList(); // creates an array list of just the 19 most common CWEs
		for (CWE objCwe: nistCWEs ) { //loops through all the CWE entries in the CWE list
			for (int year=begYear; year<=endYear; year++){
				// find the number of vulnerabilities and update the CWE object accordingly 
				searchByCweIdAndYear(objCwe, year) ;
			}
			
		}

		System.out.print("CWE-ID\t CWE-Name\t Category \t Is Part Of NIST19"); //header for the list of CWEs
		for (int year=begYear; year<=endYear; year++){ //prints all the years data was collected
			System.out.print("\t" + year);
		}

		//outputs all CWEs to console and textfile
		objCweList.printAllNISTCWEs(); 
		objCweList.printAllNistCWEsToFile("NumOfVulnNist19ByYear.txt");
	}
	
	/**
	 * Generate a URL for searching for a particular CWE-ID vulnerability
	 * @param cwe a single CWE object, representing a single CWE category
	 */
	public static void searchByCweId(CWE cwe){
		
		String urlString = "https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&cwe_id=CWE-" + cwe.getId(); //url of the desired CWE
		
		try {
			URL url = new URL(urlString);
			
			BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream())); //creates a stream from the URL of the CWE
			
			String strLine = "";
			String patternRegEx = "(.*)There are <strong(.*)>(.*)</strong> matching records(.*)";
			Pattern pattern = Pattern.compile(patternRegEx);//compiles the regular expression into a pattern;exception can be thrown
		    Matcher matcher; //object that performs match operations on a pattern sequence
		    
			while (null != (strLine = br.readLine())) { //loops through all the lines in the webpage 
				
				matcher = pattern.matcher(strLine);	//creates a matcher that will match the given input against this pattern 
				if (matcher.matches()){ //this tries to match the entire region against the pattern
					int numOfVuln = Integer.parseInt(matcher.group(3).replaceAll(",","")); //strip all commas in the matched group
					System.out.println("CWE-"+ cwe.getId() + ": " + cwe.getName() + ": " 
											+ cwe.getType() + " : " + numOfVuln);//prints out the CWE along with its vulnerabilities
					cwe.setNumOfVuln(numOfVuln);//updates the CWE object with its number of vulnerabilities
					break;
				}
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}	
	}
	
	/**
	 * Search and find out the number of vulnerabilities reported in a year for a particular CWE type
	 * @param cwe Common Weakness Enumeration
	 * @param year Reporting Year
	 */
	public static void searchByCweIdAndYear(CWE cwe, int year) {
			
	String urlString = "";
		
		//the different parts of the URL string being concatenated for a certain CWE and year
		urlString += "https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&cwe_id=CWE-" + cwe.getId(); 
		urlString += "&pub_start_date=01%2F01%2F" + year;
		urlString += "&pub_end_date=12%2F31%2F" + year;
		
		try {                                                             

			URL url = new URL(urlString);

			BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));//creates a stream for the URLof the CWE with its year
			
			String strLine = "";
			String patternRegEx = "(.*)There are <strong(.*)>(.*)</strong> matching records(.*)";
			Pattern pattern = Pattern.compile(patternRegEx);//compiles the string expression into a pattern;exception can be thrown
		    Matcher matcher;//object that performs match operations on a pattern sequence 
		    
			while (null != (strLine = br.readLine())) {//loops through all the lines in a webpage 
				matcher = pattern.matcher(strLine);	//creates a matcher that will match the given input against the pattern 
				
				if (matcher.matches()){//test if the entire region matches against the pattern
					
					int numOfVuln = Integer.parseInt(matcher.group(3).replaceAll(",","")); //strip all commas in the matched group
					System.out.println("CWE-"+ cwe.getId() + ": " + cwe.getName() 
										+ ": " + cwe.getType() + ": " + year + ":" + numOfVuln);//prints out the CWE/Year with its frequency
					
					//cwe.setNumOfVuln(numOfVuln);
					cwe.addNumVulnInYear(year, numOfVuln);//updates the CWE object with its number of vulnerabilities
					break;
				}
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}	
			
	}
	
	public static void searchByProductAndYear(CWE cwe, String vendor, String product, int year)
	{
		String urlString = "";
		
		//the different parts of the URL string being concatenated for a certain CWE and year
		urlString += "https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&cwe_id=CWE-" + cwe.getId(); 
		urlString += "&cpe_vendor=cpe%3A%2F%3A" + vendor;
		urlString += "&cpe_product=cpe%3A%2F%3A%3A" + product;
		urlString += "&pub_start_date=01%2F01%2F" + year;
		urlString += "&pub_end_date=12%2F31%2F" + year;
		
		try {                                                             

			URL url = new URL(urlString);

			BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));//creates a stream for the URLof the CWE with its year
			
			String strLine = "";
			String patternRegEx = "(.*)There are <strong(.*)>(.*)</strong> matching records(.*)";
			Pattern pattern = Pattern.compile(patternRegEx);//compiles the string expression into a pattern;exception can be thrown
		    Matcher matcher;//object that performs match operations on a pattern sequence 
		    
			while (null != (strLine = br.readLine())) {//loops through all the lines in a webpage 
				matcher = pattern.matcher(strLine);	//creates a matcher that will match the given input against the pattern 
				
				if (matcher.matches()){//test if the entire region matches against the pattern
					
					int numOfVuln = Integer.parseInt(matcher.group(3).replaceAll(",","")); //strip all commas in the matched group
					System.out.println("CWE-"+ cwe.getId() + ": " + cwe.getName() 
										+ ": " + cwe.getType() + ": " + year + ":" + numOfVuln);//prints out the CWE/Year with its frequency
					
					//cwe.setNumOfVuln(numOfVuln);
					cwe.addNumVulnInYear(year, numOfVuln);//updates the CWE object with its number of vulnerabilities
					break;
				}
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}	
	}
	
	/** Given a particular year, find out the total number of vulnerabilities reported in that year
	 * @param year single calendar year
	 * @return the number of vulnerabilities in a year
	 */
	public static int vulnReportedInAYear(int year){
		
		//concatenation of the URL string for a given year
		String urlString = "";
		urlString += "https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all"; 
		urlString += "&pub_start_date=01%2F01%2F" + year;
		urlString += "&pub_end_date=12%2F31%2F" + year;
				
		try {
				URL url = new URL(urlString);
				BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));//creates a stream given the URL
				
				String strLine = "";
				String patternRegEx = "(.*)There are <strong(.*)>(.*)</strong> matching records(.*)";
				Pattern pattern = Pattern.compile(patternRegEx);//compiles the string expression into a pattern;exception can be throw 
			    Matcher matcher;//object that performs match operations on a pattern sequence 
			    
				while (null != (strLine = br.readLine())) {//loops through all the lines in the NVD for the given entry
					
					matcher = pattern.matcher(strLine);//creates a matcher object that will match the given input against a pattern	
					if (matcher.matches()){ //tests if the entire region maps against a certain pattern
						int numOfVuln = Integer.parseInt(matcher.group(3).replaceAll(",","")); //strip all commas in the matched gropu
						System.out.println(year + ": " + numOfVuln);// outputs the number of vulnerabilities in a given year
						
						return numOfVuln; //returns the count of vulnerabilities for that year
					}
				}
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}	
		return -1;
	}// end method vulnReportedInAYear
	
	
} // end class
