import { useEffect, useState } from "react";

import axios from "axios";

import {

  PieChart,

  Pie,

  Cell,

  Tooltip,

  ResponsiveContainer,

} from "recharts";

import "./App.css";



const API = "http://127.0.0.1:5000";



function App() {

  const [stats, setStats] = useState({

    total_packets: 0,

    total_bytes: 0,

    protocols: {},

  });



  const [traffic, setTraffic] = useState([]);

  const [alerts, setAlerts] = useState([]);



  const [captureRunning, setCaptureRunning] = useState(false);

  const [interfaceName, setInterfaceName] = useState("");



  const [lastUpdated, setLastUpdated] = useState("");

  const [loading, setLoading] = useState(false);



  // ---------------------------------------

  // PCAP States

  // ---------------------------------------



  const [pcapFile, setPcapFile] = useState(null);

  const [pcapResult, setPcapResult] = useState(null);

  const [pcapLoading, setPcapLoading] = useState(false);

  const [pcapError, setPcapError] = useState("");

  // ---------------------------------------
  // Agent States
  // ---------------------------------------

  const [agentPackets, setAgentPackets] = useState([]);
  const [agentActive, setAgentActive] = useState(false);
  const [agentLoading, setAgentLoading] = useState(false);






  // ---------------------------------------

  // Load Dashboard Data

  // ---------------------------------------



  const loadData = async () => {

    try {

      const [

        statsResponse,

        trafficResponse,

        alertsResponse,

      ] = await Promise.all([

        axios.get(`${API}/api/stats`),

        axios.get(`${API}/api/traffic`),

        axios.get(`${API}/api/alerts`),

      ]);



      setStats(statsResponse.data);



      setTraffic(

        trafficResponse.data

      );



      setAlerts(

        alertsResponse.data.alerts

      );



      setLastUpdated(

        new Date().toLocaleTimeString()

      );



    } catch (error) {

      console.error(

        "Error loading dashboard data:",

        error

      );

    }

  };





  // ---------------------------------------

  // Load Capture Status

  // ---------------------------------------



  const loadCaptureStatus = async () => {

    try {

      const response = await axios.get(

        `${API}/api/capture/status`

      );



      setCaptureRunning(

        response.data.running

      );



      setInterfaceName(

        response.data.interface

      );



    } catch (error) {

      console.error(

        "Error loading capture status:",

        error

      );

    }

  };





  // ---------------------------------------
  // Load Agent Traffic
  // ---------------------------------------

  const loadAgentTraffic = async () => {
    try {
      setAgentLoading(true);

      const response = await axios.get(
        `${API}/api/agent/traffic`
      );

      setAgentActive(
        response.data.agent_active
      );

      setAgentPackets(
        response.data.packets || []
      );

    } catch (error) {
      console.error(
        "Error loading agent traffic:",
        error
      );
    } finally {
      setAgentLoading(false);
    }
  };


  // ---------------------------------------

  // Start Capture

  // ---------------------------------------



  const startCapture = async () => {

    try {

      setLoading(true);



      await axios.post(

        `${API}/api/capture/start`

      );



      await loadCaptureStatus();



    } catch (error) {

      console.error(

        "Error starting capture:",

        error

      );



    } finally {

      setLoading(false);

    }

  };





  // ---------------------------------------

  // Stop Capture

  // ---------------------------------------



  const stopCapture = async () => {

    try {

      setLoading(true);



      await axios.post(

        `${API}/api/capture/stop`

      );



      await loadCaptureStatus();



    } catch (error) {

      console.error(

        "Error stopping capture:",

        error

      );



    } finally {

      setLoading(false);

    }

  };





  // ---------------------------------------

  // PCAP File Selection

  // ---------------------------------------



  const handlePcapChange = (event) => {

    const file =

      event.target.files[0];



    setPcapError("");

    setPcapResult(null);



    if (!file) {

      setPcapFile(null);

      return;

    }



    const filename =

      file.name.toLowerCase();



    if (

      !filename.endsWith(".pcap") &&

      !filename.endsWith(".pcapng")

    ) {

      setPcapFile(null);



      setPcapError(

        "Please select a .pcap or .pcapng file."

      );



      return;

    }



    setPcapFile(file);

  };





  // ---------------------------------------

  // Analyze PCAP

  // ---------------------------------------



  const analyzePcap = async () => {

    if (!pcapFile) {

      setPcapError(

        "Please select a PCAP file first."

      );

      return;

    }



    try {

      setPcapLoading(true);

      setPcapError("");

      setPcapResult(null);



      const formData =

        new FormData();



      formData.append(

        "file",

        pcapFile

      );



      const response =

        await axios.post(

          `${API}/api/pcap/upload`,

          formData,

          {

            headers: {

              "Content-Type":

                "multipart/form-data",

            },

          }

        );



      setPcapResult(

        response.data

      );



    } catch (error) {

      console.error(

        "PCAP analysis error:",

        error

      );



      setPcapError(

        error.response?.data?.message ||

        "Unable to analyze PCAP file."

      );



    } finally {

      setPcapLoading(false);

    }

  };





  // ---------------------------------------

  // Auto Refresh

  // ---------------------------------------



  useEffect(() => {
    loadData();
    loadCaptureStatus();
    loadAgentTraffic();

    const interval =
      setInterval(() => {
        loadData();
        loadCaptureStatus();
        loadAgentTraffic();
      }, 5000);

    return () =>
      clearInterval(interval);
  }, []);





  // ---------------------------------------

  // Live Protocol Chart

  // ---------------------------------------



  const protocolData =

    Object.entries(

      stats.protocols || {}

    ).map(([name, value]) => ({

      name,

      value,

    }));





  // ---------------------------------------

  // PCAP Protocol Chart

  // ---------------------------------------



  const pcapProtocolData =

    pcapResult

      ? Object.entries(

          pcapResult.protocols || {}

        ).map(([name, value]) => ({

          name,

          value,

        }))

      : [];





  // ---------------------------------------

  // PCAP Packet Data

  // ---------------------------------------



  const pcapPackets =

    pcapResult?.packets || [];





  return (

    <div className="app">





      {/* =====================================

          HEADER

      ====================================== */}



      <header className="header">



        <div>



          <h1>

            Network Security Center

          </h1>



          <p>

            Real-Time Network Traffic Monitoring

          </p>



        </div>





        <div

          className={

            captureRunning

              ? "live-badge"

              : "live-badge stopped"

          }

        >



          <span className="status-dot"></span>



          {captureRunning

            ? "LIVE MONITORING"

            : "CAPTURE STOPPED"}



        </div>



      </header>





      {/* =====================================

          LIVE CAPTURE CONTROL

      ====================================== */}



      <section className="capture-control">



        <div className="capture-info">



          <h2>

            Network Capture

          </h2>



          <p>

            Interface:{" "}

            <strong>

              {interfaceName ||

                "Loading..."}

            </strong>

          </p>



          <p>

            Status:{" "}

            <strong>

              {captureRunning

                ? "Capturing live traffic"

                : "Capture stopped"}

            </strong>

          </p>



        </div>





        <div className="capture-buttons">



          <button

            className="start-button"

            onClick={startCapture}

            disabled={

              captureRunning ||

              loading

            }

          >

            ▶ Start Capture

          </button>





          <button

            className="stop-button"

            onClick={stopCapture}

            disabled={

              !captureRunning ||

              loading

            }

          >

            ■ Stop Capture

          </button>



        </div>



      </section>





      {/* =====================================
          AGENT LAPTOP MONITORING
      ====================================== */}

      <section className="panel traffic-panel">

        <div className="panel-header">

          <div>
            <h2>Agent Laptop Traffic</h2>

            <p className="pcap-description">
              Network traffic captured from the
              user's laptop through the security agent.
            </p>

            <a
              href="/NetworkSecurityAgent.exe"
              download
              style={{
                display: "inline-block",
                marginTop: "14px",
                padding: "11px 18px",
                borderRadius: "8px",
                background: "#16a34a",
                color: "#ffffff",
                textDecoration: "none",
                fontWeight: 600,
                fontSize: "14px"
              }}
            >
              ↓ Download Security Agent
            </a>
          </div>

          <div
            className={
              agentActive
                ? "live-badge"
                : "live-badge stopped"
            }
          >
            <span className="status-dot"></span>

            {agentActive
              ? "AGENT CONNECTED"
              : "AGENT OFFLINE"}
          </div>

        </div>

        <div className="stats-grid">

          <div className="stat-card">

            <h3>Agent Packets</h3>

            <div className="stat-value">
              {agentPackets.length}
            </div>

          </div>

          <div className="stat-card">

            <h3>Agent Status</h3>

            <div
              className={
                agentActive
                  ? "system-online"
                  : "system-offline"
              }
            >
              {agentActive
                ? "CONNECTED"
                : "OFFLINE"}
            </div>

          </div>

        </div>

        <div className="table-container">

          {agentPackets.length > 0 ? (

            <table>

              <thead>

                <tr>
                  <th>Time</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Protocol</th>
                  <th>Source Port</th>
                  <th>Destination Port</th>
                  <th>Size</th>
                </tr>

              </thead>

              <tbody>

                {agentPackets
                  .slice(-50)
                  .reverse()
                  .map((packet, index) => (

                    <tr key={index}>

                      <td>
                        {packet.timestamp}
                      </td>

                      <td>
                        {packet.source_ip}
                      </td>

                      <td>
                        {packet.destination_ip}
                      </td>

                      <td>
                        <span className="protocol">
                          {packet.protocol}
                        </span>
                      </td>

                      <td>
                        {packet.source_port}
                      </td>

                      <td>
                        {packet.destination_port}
                      </td>

                      <td>
                        {packet.packet_size} bytes
                      </td>

                    </tr>

                  ))}

              </tbody>

            </table>

          ) : (

            <div className="empty-state">

              {agentLoading
                ? "Loading agent traffic..."
                : "No agent traffic received yet."}

            </div>

          )}

        </div>

      </section>


      {/* =====================================

          PCAP FILE ANALYSIS

      ====================================== */}



      <section className="panel pcap-panel">



        <div className="panel-header">



          <div>



            <h2>

              PCAP File Analysis

            </h2>



            <p className="pcap-description">

              Upload a .pcap or .pcapng

              file for security analysis.

            </p>



          </div>



        </div>





        <div className="pcap-upload-area">



          <input

            type="file"

            accept=".pcap,.pcapng"

            onChange={handlePcapChange}

          />





          {pcapFile && (

            <div className="selected-file">



              Selected File:



              <strong>

                {pcapFile.name}

              </strong>



            </div>

          )}





          <button

            className="analyze-pcap-button"

            onClick={analyzePcap}

            disabled={

              !pcapFile ||

              pcapLoading

            }

          >



            {pcapLoading

              ? "Analyzing..."

              : "Analyze PCAP"}



          </button>





          {pcapError && (

            <div className="pcap-error">

              ⚠ {pcapError}

            </div>

          )}



        </div>



      </section>





      {/* =====================================

          PCAP RESULTS

      ====================================== */}



      {pcapResult && (



        <section className="pcap-results">





          {/* =================================

              PCAP SUMMARY

          ================================= */}



          <div className="panel">



            <h2>

              PCAP Analysis Result

            </h2>



            <p className="pcap-file-name">



              File:



              <strong>

                {pcapResult.filename}

              </strong>



            </p>





            <div className="stats-grid">



              <div className="stat-card">



                <h3>

                  Packets

                </h3>



                <div className="stat-value">

                  {pcapResult.total_packets}

                </div>



              </div>





              <div className="stat-card">



                <h3>

                  Traffic

                </h3>



                <div className="stat-value">

                  {pcapResult.total_bytes.toLocaleString()}

                </div>



                <span>

                  bytes

                </span>



              </div>





              <div className="stat-card">



                <h3>

                  Security Alerts

                </h3>



                <div className="stat-value">

                  {pcapResult.total_alerts}

                </div>



              </div>





              <div className="stat-card">



                <h3>

                  Analysis Status

                </h3>



                <div className="system-online">

                  ANALYZED

                </div>



              </div>



            </div>



          </div>





          {/* =================================

              PCAP CHART + ALERTS

          ================================= */}



          <div className="main-grid">





            {/* PCAP PROTOCOL CHART */}



            <div className="panel">



              <h2>

                PCAP Protocol Distribution

              </h2>



              <div className="chart-container">



                {pcapProtocolData.length > 0 ? (



                  <ResponsiveContainer

                    width="100%"

                    height={300}

                  >



                    <PieChart>



                      <Pie

                        data={

                          pcapProtocolData

                        }

                        dataKey="value"

                        nameKey="name"

                        cx="50%"

                        cy="50%"

                        outerRadius={100}

                        label

                      >



                        {pcapProtocolData.map(

                          (entry, index) => (



                            <Cell

                              key={

                                `pcap-cell-${index}`

                              }

                            />



                          )

                        )}



                      </Pie>



                      <Tooltip />



                    </PieChart>



                  </ResponsiveContainer>



                ) : (



                  <div className="empty-state">

                    No protocol data available

                  </div>



                )}



              </div>



            </div>





            {/* PCAP ALERTS */}



            <div className="panel">



              <h2>

                PCAP Security Alerts

              </h2>





              {pcapResult.alerts?.length === 0 ? (



                <div className="no-alerts">

                  ✓ No suspicious ports detected

                </div>



              ) : (



                <div className="alerts-list">



                  {pcapResult.alerts.map(

                    (alert, index) => (



                      <div

                        className="alert-item"

                        key={index}

                      >



                        <strong>

                          {alert.service}

                        </strong>



                        <span>

                          Port {alert.port}

                        </span>



                        <small>

                          {alert.protocol}

                        </small>



                      </div>



                    )

                  )}



                </div>



              )}



            </div>



          </div>





          {/* =================================

              PCAP NETWORK TRAFFIC TABLE

          ================================= */}



          <section className="panel traffic-panel">



            <div className="panel-header">



              <div>



                <h2>

                  PCAP Network Traffic

                </h2>



                <p className="pcap-description">

                  Actual packets extracted from the uploaded capture

                </p>



              </div>



              <div className="pcap-packet-count">



                {pcapPackets.length.toLocaleString()} packets



              </div>



            </div>





            <div className="table-container">



              {pcapPackets.length > 0 ? (



                <table>



                  <thead>



                    <tr>



                      <th>

                        Time

                      </th>



                      <th>

                        Source IP

                      </th>



                      <th>

                        Destination IP

                      </th>



                      <th>

                        Protocol

                      </th>



                      <th>

                        Source Port

                      </th>



                      <th>

                        Destination Port

                      </th>



                      <th>

                        Size

                      </th>



                    </tr>



                  </thead>





                  <tbody>



                    {pcapPackets

                      .map(

                        (packet, index) => (



                          <tr

                            key={`pcap-packet-${index}`}

                          >



                            <td>

                              {packet["Timestamp"]}

                            </td>



                            <td>

                              {packet["Source IP"]}

                            </td>



                            <td>

                              {packet["Destination IP"]}

                            </td>



                            <td>



                              <span className="protocol">

                                {packet["Protocol"]}

                              </span>



                            </td>



                            <td>

                              {packet["Source Port"] || "-"}

                            </td>



                            <td>

                              {packet["Destination Port"] || "-"}

                            </td>



                            <td>

                              {packet["Packet Size"]}

                              {" bytes"}

                            </td>



                          </tr>



                        )

                      )}



                  </tbody>



                </table>



              ) : (



                <div className="empty-state">



                  No packet data available in this capture.



                </div>



              )}



            </div>



          </section>



        </section>



      )}





      {/* =====================================

          LIVE STAT CARDS

      ====================================== */}



      <section className="stats-grid">



        <div className="stat-card">



          <h3>

            Total Packets

          </h3>



          <div className="stat-value">

            {stats.total_packets}

          </div>



        </div>





        <div className="stat-card">



          <h3>

            Total Traffic

          </h3>



          <div className="stat-value">

            {stats.total_bytes.toLocaleString()}

          </div>



          <span>

            bytes

          </span>



        </div>





        <div className="stat-card">



          <h3>

            Security Alerts

          </h3>



          <div className="stat-value">

            {alerts.length}

          </div>



        </div>





        <div className="stat-card">



          <h3>

            System Status

          </h3>



          <div

            className={

              captureRunning

                ? "system-online"

                : "system-offline"

            }

          >



            {captureRunning

              ? "ONLINE"

              : "STOPPED"}



          </div>



        </div>



      </section>





      {/* =====================================

          LIVE DATA GRID

      ====================================== */}



      <section className="main-grid">





        {/* LIVE PROTOCOL CHART */}



        <div className="panel">



          <h2>

            Protocol Distribution

          </h2>



          <div className="chart-container">



            {protocolData.length > 0 ? (



              <ResponsiveContainer

                width="100%"

                height={300}

              >



                <PieChart>



                  <Pie

                    data={protocolData}

                    dataKey="value"

                    nameKey="name"

                    cx="50%"

                    cy="50%"

                    outerRadius={100}

                    label

                  >



                    {protocolData.map(

                      (entry, index) => (



                        <Cell

                          key={`cell-${index}`}

                        />



                      )

                    )}



                  </Pie>



                  <Tooltip />



                </PieChart>



              </ResponsiveContainer>



            ) : (



              <div className="empty-state">

                No traffic data available

              </div>



            )}



          </div>



        </div>





        {/* LIVE SECURITY ALERTS */}



        <div className="panel">



          <h2>

            Security Alerts

          </h2>





          {alerts.length === 0 ? (



            <div className="no-alerts">

              ✓ No suspicious ports detected

            </div>



          ) : (



            <div className="alerts-list">



              {alerts.map(

                (alert, index) => (



                  <div

                    className="alert-item"

                    key={index}

                  >



                    <strong>

                      {alert.service}

                    </strong>



                    <span>

                      Port {alert.port}

                    </span>



                    <small>

                      {alert.source_ip}

                    </small>



                  </div>



                )

              )}



            </div>



          )}



        </div>



      </section>





      {/* =====================================

          LIVE TRAFFIC TABLE

      ====================================== */}



      <section className="panel traffic-panel">



        <div className="panel-header">



          <h2>

            Network Traffic

          </h2>





          <button

            className="refresh-button"

            onClick={() => {



              loadData();

              loadCaptureStatus();



            }}

          >



            ↻ Refresh



          </button>



        </div>





        <div className="table-container">



          <table>



            <thead>



              <tr>



                <th>

                  Time

                </th>



                <th>

                  Source IP

                </th>



                <th>

                  Destination IP

                </th>



                <th>

                  Protocol

                </th>



                <th>

                  Source Port

                </th>



                <th>

                  Destination Port

                </th>



                <th>

                  Size

                </th>



              </tr>



            </thead>





            <tbody>



              {traffic

                .slice(-50)

                .reverse()

                .map(

                  (packet, index) => (



                    <tr

                      key={index}

                    >



                      <td>

                        {packet["Timestamp"]}

                      </td>



                      <td>

                        {packet["Source IP"]}

                      </td>



                      <td>

                        {packet["Destination IP"]}

                      </td>



                      <td>



                        <span className="protocol">

                          {packet["Protocol"]}

                        </span>



                      </td>



                      <td>

                        {packet["Source Port"]}

                      </td>



                      <td>

                        {packet["Destination Port"]}

                      </td>



                      <td>



                        {packet["Packet Size"]}

                        {" bytes"}



                      </td>



                    </tr>



                  )

                )}



            </tbody>



          </table>



        </div>



      </section>





      {/* =====================================

          FOOTER

      ====================================== */}



      <footer>



        Last Updated:{" "}

        {lastUpdated}



      </footer>



    </div>

  );

}



export default App;