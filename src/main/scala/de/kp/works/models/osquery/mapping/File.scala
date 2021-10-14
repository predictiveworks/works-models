package de.kp.works.models.osquery.mapping

object File extends Yaml {

  val spec: String =
    """
      |author: Dr. Stefan Krusche
      |comment:
      |table: File
      |node: File
      |entities: File, Directory, User, Group, Device
      |#
      |# Node properties of the 'File' node
      |#
      |properties:
      |  - filename
      |  - path
      |  - inode
      |  - mode
      |  - size
      |  - block_size
      |  - atime
      |  - mtime
      |  - ctime
      |  - btime
      |  - hard_links
      |  - symlink
      |  - type
      |  - attributes
      |  - volume_serial
      |  - file_id
      |  - product_version
      |  - bsd_flags
      |  - pid_with_namespace
      |  - mount_namespace_id
      |edges:
      |  - direction: out
      |    # Directory of file(s)
      |    label: directory
      |    node:
      |      name: Directory
      |      value: directory
      |  - direction: out
      |    label: uid
      |    node:
      |      name: User
      |      value: uid
      |  - direction: out
      |    label: gid
      |    node:
      |      name: Group
      |      value: gid
      |  - direction: out
      |    label: device
      |    node:
      |      name: Device
      |      value: device
      |""".stripMargin

  def main(args:Array[String]):Unit = {
    println(fromStr(spec))
  }
}
