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
 *
 * OPEN ISSUE: Modeling the TIME like event (at) time
 *
 * Should we define a time window where all events
 * refer to? In the sense of a snapshot in time?
 */
object ConnApp extends BaseApp {

  def transform(json:JsonObject, hostname:String):(Seq[Vertex], Seq[Edge]) = {
    /*
     * CONNECTION
     *
     * The connection node aggregates the connection
     * specific fields and also serves as a connector
     * to the corresponding IP addresses and ports
     */
    val localAddr = json.get(LOCAL_ADDRESS).getAsString
    val localPort = getValue(json, LOCAL_PORT)

    val remoteAddr = json.get(REMOTE_ADDRESS).getAsString
    val remotePort = getValue(json, REMOTE_PORT)

    val family = getFamily(json)
    val protocol = getProtocol(json)

    val addrProps = Map(
      FAMILY   -> Seq("STRING", family),
      PROTOCOL -> Seq("STRING", protocol)
    )

    /*
     * The unique connection identifier is built without
     * including `family` as this enables to join data
     * with Zeek logs
     */
    val connId = buildHash(Seq(hostname, protocol, localAddr, remoteAddr, localPort, remotePort))
    vertices += Vertex(
      id = connId, idType = "STRING", label = family)

    /*
     * IP ADDRESS (local) -- (local_address) --> CONN
     */
    val localAddrId = buildHash(Seq(hostname, localAddr))
    vertices += Vertex(
      id = localAddrId, idType = "STRING", label = localAddr, properties = Some(addrProps))

    edges += Edge(
      id = buildHash(Seq(hostname, connId, localAddrId)),
      idType = "STRING",
      label = LOCAL_ADDRESS,
      fromId = localAddrId,
      fromIdType = "STRING",
      toId = connId,
      toIdType = "STRING")

    /*
     * IP ADDRESS (remote) <-- (remote_address) -- CONN
     */
    val remoteAddrId = buildHash(Seq(hostname, remoteAddr))
    vertices += Vertex(
      id = remoteAddrId, idType = "STRING", label = remoteAddr, properties = Some(addrProps))

    edges += Edge(
      id = buildHash(Seq(hostname, connId, remoteAddrId)),
      idType = "STRING",
      label = REMOTE_ADDRESS,
      fromId = connId,
      fromIdType = "STRING",
      toId = remoteAddrId,
      toIdType = "STRING")

    /*
     * PORT (local) -- (local_port) --> CONN
     */
    val localPortId = buildHash(Seq(hostname, localPort))
    vertices += Vertex(
      id = localPortId, idType = "STRING", label = localPort)

    edges += Edge(
      id = buildHash(Seq(hostname, connId, localPortId)),
      idType = "STRING",
      label = LOCAL_PORT,
      fromId = localPortId,
      fromIdType = "STRING",
      toId = connId,
      toIdType = "STRING")

    /*
     * PORT (remote) <-- (remote_address) -- CONN
     */
    val remotePortId = buildHash(Seq(hostname, remotePort))
    vertices += Vertex(
      id = remotePortId, idType = "STRING", label = remotePort)

    edges += Edge(
      id = buildHash(Seq(hostname, connId, remotePortId)),
      idType = "STRING",
      label = REMOTE_PORT,
      fromId = connId,
      fromIdType = "STRING",
      toId = remotePortId,
      toIdType = "STRING")

    /*
     * PROCESS -- (has_conn) --> CONN
     *
     * Open network sockets (or connections) refer to
     * running processes, and the process reference is
     * extracted as vertex
     */
    val pid = getValue(json, PID)

    val processId = buildHash(Seq(hostname, pid))
    vertices += Vertex(
      id = processId, idType = "STRING", label = pid)

    edges += Edge(
      id = buildHash(Seq(hostname, processId, connId)),
      idType = "STRING",
      label = HAS_CONN,
      fromId = processId,
      fromIdType = "STRING",
      toId = connId,
      toIdType = "STRING")

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
    val fd = getValue(json, FD)
    val socket = getValue(json, SOCKET)

    val path = json.get(PATH).getAsString
    val state = json.get(STATE).getAsString

    val socketProps = Map(
      FD    -> Seq("LONG", fd),
      PATH  -> Seq("STRING", path),
      STATE -> Seq("STRING", state)
    )

    val socketId = buildHash(Seq(hostname, fd, socket))
    vertices += Vertex(
      id = socketId, idType = "STRING", label = fd, properties = Some(socketProps))

    edges += Edge(
      id = buildHash(Seq(hostname, processId, socketId)),
      idType = "STRING",
      label = HAS_SOCKET,
      fromId = processId,
      fromIdType = "STRING",
      toId = socketId,
      toIdType = "STRING")

    (vertices, edges)

  }

  private def getValue(json:JsonObject, name:String):String = {
    val value = json.get(name).getAsJsonPrimitive
    if (value.isNumber) value.getAsLong.toString else value.getAsString
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
