package de.kp.works.models.osquery.mapping

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.google.gson.{JsonObject, JsonParser}

import java.net.URI
import java.nio.file.{Files, Paths}

trait Yaml {

  def fromUri(uri:URI):JsonObject = {
    /*
     * Read YAML file from URI and convert
     * convent into a Java Object
     */
    val content = new String(Files.readAllBytes(Paths.get(uri)))
    fromStr(content)

  }

  def fromStr(content:String):JsonObject = {

    val reader = new ObjectMapper(new YAMLFactory())
    val obj = reader.readValue(content, classOf[Object])
    /*
     * Leverage Java Object and convert into
     * a String
     */
    val writer = new ObjectMapper()
    val json = writer.writeValueAsString(obj)
    /*
     * Use GSON to convert JSON String into JsonObject
     */
    JsonParser.parseString(json).getAsJsonObject

  }
}
