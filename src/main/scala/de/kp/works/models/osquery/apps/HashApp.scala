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

/**
 * HashApp transforms a Hash log entry into nodes
 * and edges; it refers to table `hash`.
 *
 * A `hash` value is associated with a file on the
 * file system, and is expected to be a more or less
 * static information.
 *
 * The result contributes to the `hash` (sub) graph
 * model of the Osquery Graph.
 */
object HashApp extends BaseApp {
  /*
   * The nodes that refer to columns
   */
  private val nodes = List("md5", "sha1", "sha256", "ssdeep")
  /**
   * This methods transforms an Osquery hash entry
   * into the following sub graph
   *
   * Host -- (has_file) --> File -- (has_hash) --> Hash (md5, sha1, etc)
   */
  def transform(json:JsonObject, hostname:String):Unit = {

    /*
     * HOST
     *
     * The current implementation links the host to the
     * file that is described by the hash values
     */
    val hostId = buildHashValue(Seq("host", hostname))
    vertices += Vertex(id = hostId, idType = "STRING", label = hostname)
    /*
     * HASH VALUES
     */
    nodes.foreach(node => {

      if (json.has(node)) {

        val hash = json.get(node).getAsString
        val hashProps = Map(TYPE -> Seq("STRING", "hash"))
        /*
         * The hash value is expected to be a more or
         * less static information
         */
        val hashId = buildHashValue(Seq("hash", hash))
        vertices += Vertex(id = hashId, idType = "STRING", label = hash, properties = Some(hashProps))
        /*
         * The hash log entry usually also references
         * the assigned file, which is identified via
         * columns `path` and `directory`.
         *
         * The current implementation combines both
         * columns values as unique identifier of the
         * this file
         */
        if (json.has(PATH) && json.has(DIRECTORY)) {

          val path = json.get(PATH).getAsString
          val directory = json.get(DIRECTORY).getAsString

          /*
           * The `file` vertex is defined as the head of
           * the edge; its identifier is built from path.
           *
           * The `path` field is used (and not a combination
           * with directory), we expect here that
           *
           * (a) directory can be derived from path
           *
           * (b) other log events like processes refers files
           * via path only
           */
          val fileId = buildHashValue(Seq("file", path))
          val fileProps = Map(DIRECTORY -> Seq("STRING", directory))

          vertices += fileVertex(id = fileId, label = path, props = Some(fileProps))
          /*
           * The unique identifier of the edge is built
           * from (fromId, toId, label) to avoid creating
           * continuously new edges
           *
           * File -- (has_hash) --> Hash
           */
          edges += buildEdge(fileId, hashId, HAS_HASH)
          /*
           * Host -- (has_file) --> File
           *
           * The current implementation links the Host
           * to the File node only.
           */
          edges += buildEdge(hostId, fileId, HAS_FILE)
        }
      }

    })

    (vertices, edges)

  }
}
