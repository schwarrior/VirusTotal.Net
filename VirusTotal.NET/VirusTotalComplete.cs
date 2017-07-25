using System;
using System.IO;
using System.Threading.Tasks;
using VirusTotalNET.Results;

namespace VirusTotalNET
{
    public class VirusTotalComplete
    {
        private readonly VirusTotal _virusTotal;

        /// <summary>
        /// Public constructor for VirusTotalComplete
        /// </summary>
        /// <param name="apiKey">The API key you got from Virus Total</param>
        public VirusTotalComplete(string apiKey)
        {
            _virusTotal = new VirusTotal(apiKey);
        }

        /// <summary>
        /// Performs a file scan.
        /// First checks if there is an existing file report. 
        /// If no existing file report found at VT requests a new file report.
        /// Then checks every thirty seconds for a result. 
        /// Doesn't return until VT results come in. Can take up to five minutes
        /// </summary>
        /// <param name="fileInfo"></param>
        /// <param name="delayBetweenRequestsMs">Virus Total only allows up to 4 request per minute. This delay adds a pause between each api call. Avoids exceptions. Defaults to 30.5 seconds.</param>
        /// <returns>A Tuple. Item 1 is a detection ratio (a float derived from positives divided by total). Item 2 is Virus Total permalink for scan.</returns>
        public async Task<Tuple<float, string>> ScanFileComplete(FileInfo fileInfo, int delayBetweenRequestsMs = 30500)
        {
            Console.WriteLine($"Getting File Report: {fileInfo.FullName}");

            var fileReport = await _virusTotal.GetFileReport(fileInfo);
            var scanId = string.Empty;

            while (fileReport.ResponseCode != ResponseCodes.ReportResponseCode.Present)
            {
                if (string.IsNullOrEmpty(scanId))
                {
                    Console.WriteLine($"Waiting {delayBetweenRequestsMs} ms");
                    await Task.Delay(delayBetweenRequestsMs);
                    var scanResult = await _virusTotal.ScanFile(fileInfo);
                    scanId = scanResult.ScanId;
                    Console.WriteLine($"scanId: {scanId}");
                }
                Console.WriteLine($"Waiting {delayBetweenRequestsMs} ms");
                await Task.Delay(delayBetweenRequestsMs);
                fileReport = await _virusTotal.GetFileReport(scanId);
            }

            var detectionRatio = fileReport.Positives / (float)fileReport.Total;
            Console.WriteLine($"Detection Ratio: {fileReport.Positives} / {fileReport.Total} = {detectionRatio}");

            return new Tuple<float, string>(detectionRatio, fileReport.Permalink);
        }

        /// <summary>
        /// Performs a URL scan. 
        /// Request a URL scan.
        /// Then checks every thirty seconds for a result. 
        /// Doesn't return until VT results come in. Can take up to five minutes
        /// </summary>
        /// <param name="url"></param>
        /// <param name="delayBetweenRequestsMs">Virus Total only allows up to 4 request per minute. This delay adds a pause between each api call. Avoids exceptions. Defaults to 30.5 seconds.</param>
        /// <returns>A Tuple. Item 1 is a detection ratio (a float derived from positives divided by total). Item 2 is Virus Total permalink for scan.</returns>
        public async Task<Tuple<float, string>> ScanUrlComplete(string url, int delayBetweenRequestsMs = 30500)
        {
            Console.WriteLine($"Getting Url Report: {url}");

            await _virusTotal.ScanUrl(url);
            UrlReport urlReport = null;

            while (urlReport == null || urlReport.ResponseCode != ResponseCodes.ReportResponseCode.Present)
            {
                await Task.Delay(delayBetweenRequestsMs);
                Console.WriteLine($"Waiting {delayBetweenRequestsMs} ms");
                urlReport = await _virusTotal.GetUrlReport(url);
            }

            var detectionRatio = urlReport.Positives / (float) urlReport.Total;
            Console.WriteLine($"Detection Ratio: {urlReport.Positives} / {urlReport.Total} = {detectionRatio}");

            return new Tuple<float, string>(detectionRatio, urlReport.Permalink);
        }
        
    }
}