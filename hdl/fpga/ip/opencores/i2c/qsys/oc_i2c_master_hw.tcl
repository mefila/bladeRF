# TCL File Generated by Component Editor 13.1
# Sun Nov 24 13:25:09 EST 2013
# DO NOT MODIFY


# 
# bladerf_oc_i2c_master "BladeRF OpenCores I2C Master" v1.0
# OpenCores 2013.11.24.13:25:09
# BladeRF OpenCores I2C Master
# 

# 
# request TCL package from ACDS 13.1
# 
package require -exact qsys 13.1


# 
# module bladerf_oc_i2c_master
# 
set_module_property DESCRIPTION "BladeRF OpenCores I2C Master"
set_module_property NAME bladerf_oc_i2c_master
set_module_property VERSION 1.0
set_module_property INTERNAL false
set_module_property OPAQUE_ADDRESS_MAP true
set_module_property GROUP Communication
set_module_property AUTHOR OpenCores
set_module_property DISPLAY_NAME "BladeRF OpenCores I2C Master"
set_module_property INSTANTIATE_IN_SYSTEM_MODULE true
set_module_property EDITABLE true
set_module_property ANALYZE_HDL AUTO
set_module_property REPORT_TO_TALKBACK false
set_module_property ALLOW_GREYBOX_GENERATION false


# 
# file sets
# 
add_fileset QUARTUS_SYNTH QUARTUS_SYNTH "" ""
set_fileset_property QUARTUS_SYNTH TOP_LEVEL i2c_master_top
set_fileset_property QUARTUS_SYNTH ENABLE_RELATIVE_INCLUDE_PATHS false
add_fileset_file i2c_master_top.v VERILOG PATH ../rtl/verilog/i2c_master_top.v
add_fileset_file timescale.v VERILOG PATH ../rtl/verilog/timescale.v
add_fileset_file i2c_master_defines.v VERILOG PATH ../rtl/verilog/i2c_master_defines.v
add_fileset_file i2c_master_byte_ctrl.v VERILOG PATH ../rtl/verilog/i2c_master_byte_ctrl.v
add_fileset_file i2c_master_bit_ctrl.v VERILOG PATH ../rtl/verilog/i2c_master_bit_ctrl.v


# 
# parameters
# 
add_parameter ARST_LVL STD_LOGIC 0 ""
set_parameter_property ARST_LVL DEFAULT_VALUE 0
set_parameter_property ARST_LVL DISPLAY_NAME ARST_LVL
set_parameter_property ARST_LVL WIDTH ""
set_parameter_property ARST_LVL TYPE STD_LOGIC
set_parameter_property ARST_LVL UNITS None
set_parameter_property ARST_LVL ALLOWED_RANGES 0:1
set_parameter_property ARST_LVL DESCRIPTION ""
set_parameter_property ARST_LVL HDL_PARAMETER true


# 
# display items
# 


# 
# connection point clock_sink
# 
add_interface clock_sink clock end
set_interface_property clock_sink clockRate 0
set_interface_property clock_sink ENABLED true
set_interface_property clock_sink EXPORT_OF ""
set_interface_property clock_sink PORT_NAME_MAP ""
set_interface_property clock_sink CMSIS_SVD_VARIABLES ""
set_interface_property clock_sink SVD_ADDRESS_GROUP ""

add_interface_port clock_sink wb_clk_i clk Input 1


# 
# connection point reset_sink
# 
add_interface reset_sink reset end
set_interface_property reset_sink associatedClock clock_sink
set_interface_property reset_sink synchronousEdges DEASSERT
set_interface_property reset_sink ENABLED true
set_interface_property reset_sink EXPORT_OF ""
set_interface_property reset_sink PORT_NAME_MAP ""
set_interface_property reset_sink CMSIS_SVD_VARIABLES ""
set_interface_property reset_sink SVD_ADDRESS_GROUP ""

add_interface_port reset_sink wb_rst_i reset Input 1


# 
# connection point conduit_end
# 
add_interface conduit_end conduit end
set_interface_property conduit_end associatedClock ""
set_interface_property conduit_end associatedReset ""
set_interface_property conduit_end ENABLED true
set_interface_property conduit_end EXPORT_OF ""
set_interface_property conduit_end PORT_NAME_MAP ""
set_interface_property conduit_end CMSIS_SVD_VARIABLES ""
set_interface_property conduit_end SVD_ADDRESS_GROUP ""

add_interface_port conduit_end scl_pad_o export Output 1
add_interface_port conduit_end scl_padoen_o export Output 1
add_interface_port conduit_end sda_pad_i export Input 1
add_interface_port conduit_end sda_pad_o export Output 1
add_interface_port conduit_end sda_padoen_o export Output 1
add_interface_port conduit_end arst_i export Input 1
add_interface_port conduit_end scl_pad_i export Input 1


# 
# connection point interrupt_sender
# 
add_interface interrupt_sender interrupt end
set_interface_property interrupt_sender associatedAddressablePoint bladerf_oc_i2c_master
set_interface_property interrupt_sender associatedClock clock_sink
set_interface_property interrupt_sender associatedReset reset_sink
set_interface_property interrupt_sender ENABLED true
set_interface_property interrupt_sender EXPORT_OF ""
set_interface_property interrupt_sender PORT_NAME_MAP ""
set_interface_property interrupt_sender CMSIS_SVD_VARIABLES ""
set_interface_property interrupt_sender SVD_ADDRESS_GROUP ""

add_interface_port interrupt_sender wb_inta_o irq Output 1


# 
# connection point bladerf_oc_i2c_master
# 
add_interface bladerf_oc_i2c_master avalon end
set_interface_property bladerf_oc_i2c_master addressUnits WORDS
set_interface_property bladerf_oc_i2c_master associatedClock clock_sink
set_interface_property bladerf_oc_i2c_master associatedReset reset_sink
set_interface_property bladerf_oc_i2c_master bitsPerSymbol 8
set_interface_property bladerf_oc_i2c_master burstOnBurstBoundariesOnly false
set_interface_property bladerf_oc_i2c_master burstcountUnits WORDS
set_interface_property bladerf_oc_i2c_master explicitAddressSpan 0
set_interface_property bladerf_oc_i2c_master holdTime 0
set_interface_property bladerf_oc_i2c_master linewrapBursts false
set_interface_property bladerf_oc_i2c_master maximumPendingReadTransactions 0
set_interface_property bladerf_oc_i2c_master readLatency 0
set_interface_property bladerf_oc_i2c_master readWaitTime 1
set_interface_property bladerf_oc_i2c_master setupTime 0
set_interface_property bladerf_oc_i2c_master timingUnits Cycles
set_interface_property bladerf_oc_i2c_master writeWaitTime 0
set_interface_property bladerf_oc_i2c_master ENABLED true
set_interface_property bladerf_oc_i2c_master EXPORT_OF ""
set_interface_property bladerf_oc_i2c_master PORT_NAME_MAP ""
set_interface_property bladerf_oc_i2c_master CMSIS_SVD_VARIABLES ""
set_interface_property bladerf_oc_i2c_master SVD_ADDRESS_GROUP ""

add_interface_port bladerf_oc_i2c_master wb_dat_i writedata Input 8
add_interface_port bladerf_oc_i2c_master wb_dat_o readdata Output 8
add_interface_port bladerf_oc_i2c_master wb_we_i write Input 1
add_interface_port bladerf_oc_i2c_master wb_stb_i byteenable Input 1
add_interface_port bladerf_oc_i2c_master wb_cyc_i chipselect Input 1
add_interface_port bladerf_oc_i2c_master wb_ack_o waitrequest_n Output 1
add_interface_port bladerf_oc_i2c_master wb_adr_i address Input 3
set_interface_assignment bladerf_oc_i2c_master embeddedsw.configuration.isFlash 0
set_interface_assignment bladerf_oc_i2c_master embeddedsw.configuration.isMemoryDevice 0
set_interface_assignment bladerf_oc_i2c_master embeddedsw.configuration.isNonVolatileStorage 0
set_interface_assignment bladerf_oc_i2c_master embeddedsw.configuration.isPrintableDevice 0

