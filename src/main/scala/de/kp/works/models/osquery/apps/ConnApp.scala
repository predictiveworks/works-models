package de.kp.works.models.osquery.apps
/*
 * Copyright (c) 2019 - 2021 Dr. Krusche & Partner PartG. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 * @author Stefan Krusche, Dr. Krusche & Partner PartG
 *
 */

import com.google.gson.JsonObject
import de.kp.works.models.osquery.OsqueryEnums

/**
 * The ConnApp refers to the process_open_sockets
 * table and extracts nodes end edges that refer
 * to the process & connection sub graph model.
 */
object ConnApp extends BaseApp {

  def transform(json:JsonObject, hostname:String):Unit = {

    /*
     * HOST
     *
     * The current implementation links the host
     * to the process that holds the connection
     */
    val hostId = buildHashValue(Seq("host", hostname))
    vertices += Vertex(id = hostId, idType = "STRING", label = hostname)
    /*
     * CONNECTION
     *
     * The connection node aggregates the connection
     * specific fields and also serves as a connector
     * to the corresponding IP addresses and ports
     */
    val localAddr = json.get(LOCAL_ADDRESS).getAsString
    val localPort = getLongValue(json, LOCAL_PORT)

    val remoteAddr = json.get(REMOTE_ADDRESS).getAsString
    val remotePort = getLongValue(json, REMOTE_PORT)

    val family = getFamily(json)
    val protocol = getProtocol(json)

    val addrProps = Map(
      FAMILY   -> Seq("STRING", family),
      PROTOCOL -> Seq("STRING", protocol),
      TYPE     -> Seq("STRING", "ip_address")
    )
    /*
     * The unique connection identifier is built without
     * including `family` as this enables to join data
     * with Zeek logs
     */
    val connId = buildHashValue(Seq("conn", protocol, localAddr, remoteAddr, localPort, remotePort))
    vertices += connVertex(connId, family)
    /*
     * IP ADDRESS (local) -- (local_address) --> CONN
     */
    val localAddrId = buildHashValue(Seq("ip_address", localAddr))

    vertices += addressVertex(localAddrId, localAddr, Some(addrProps))
    edges += buildEdge(connId, localAddrId, LOCAL_ADDRESS)
    /*
     * IP ADDRESS (remote) <-- (remote_address) -- CONN
     */
    val remoteAddrId = buildHashValue(Seq("ip_address", remoteAddr))

    vertices += addressVertex(remoteAddrId, remoteAddr, Some(addrProps))
    edges += buildEdge(connId, remoteAddrId, REMOTE_ADDRESS)
    /*
     * PORT (local) -- (local_port) --> CONN
     */
    val localPortId = buildHashValue(Seq("port", localPort))

    vertices += portVertex(localPortId, localPort)
    edges += buildEdge(connId, localPortId, LOCAL_PORT)
    /*
     * PORT (remote) <-- (remote_address) -- CONN
     */
    val remotePortId = buildHashValue(Seq("port", remotePort))

    vertices += portVertex(remotePortId, remotePort)
    edges += buildEdge(connId, remotePortId, REMOTE_PORT)
    /*
     * PROCESS -- (has_conn) --> CONN
     *
     * Open network sockets (or connections) refer to
     * running processes, and the process reference is
     * extracted as vertex
     */
    val pid = getLongValue(json, PID)
    val processId = buildHashValue(Seq("process", pid))

    vertices += processVertex(processId, pid)
    edges += buildEdge(processId, connId, HAS_CONN)
    /*
     * Host -- (has_process) --> Process
     */
    edges += buildEdge(hostId, processId, HAS_PROCESS)
    /*
     * SOCKET <-- (uses_socket) -- PROCESS
     *
     * Open network sockets (or connections) refer to
     * a certain socket, defined by the socket's file
     * descriptor `fd` and its `socket` handle.
     *
     * A socket is modeled as a vertex and also contains
     * `path` and `state` field.
     */
    val fd = getLongValue(json, FD)
    val socket = getLongValue(json, SOCKET)

    val path = json.get(PATH).getAsString
    val state = json.get(STATE).getAsString

    val socketProps = Map(
      FD    -> Seq("LONG",   fd),
      PATH  -> Seq("STRING", path),
      STATE -> Seq("STRING", state)
    )

    val socketId = buildHashValue(Seq("socket", fd, socket))

    vertices += socketVertex(socketId, fd, Some(socketProps))
    edges += buildEdge(processId, socketId, HAS_SOCKET)

  }

  private def getFamily(json:JsonObject):String = {

    val value = {
      val v = json.get(FAMILY).getAsJsonPrimitive
      if (v.isNumber) v.getAsInt else v.getAsString.toInt
    }

    OsqueryEnums.familyById(value)
  }

  private def getProtocol(json:JsonObject):String = {

    val value = {
      val v = json.get(PROTOCOL).getAsJsonPrimitive
      if (v.isNumber) v.getAsInt else v.getAsString.toInt
    }

    OsqueryEnums.protocolById(value)

  }
}
